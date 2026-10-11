#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#pragma pack(push, 8)
typedef struct {
    uint64_t typeName;      /* const char* */
    uint64_t fieldName;     /* const char* */
    uint64_t typeString;    /* const char* */
    int32_t  isStatic;      /* int32_t (1 - static, 0 - instance) */
    int32_t  _pad;          /* выравнивание 4 байта */
    uint64_t offset;        /* uint64_t (смещение поля или адрес) */
    uint64_t address;       /* void* (адрес статического поля) */
} VMStructEntry;
#pragma pack(pop)

#define VMSTRUCT_ENTRY_SIZE sizeof(VMStructEntry)
/* 48000 байт (0xBB80) = ровно 1000 записей VMStructEntry */
#define CHUNK_BUFFER_SIZE 0xBB80
#define LOCAL_STR_BUFFER_SIZE 0x200

typedef struct {
    uint64_t totalEntries;
    uint64_t totalTypeNames;
    uint64_t totalFieldNames;
    uint64_t totalTypeStrings;
    uint64_t totalBytesRead;
    uint64_t totalRpmCalls;
} ReadStats;

static void enable_debug_privilege(void) {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

/*
 * Чтение удаленной C-строки: читает до 0xFF байт в буфер размера 0x200.
 * Это то самое чтение, которое поднимает страницы памяти .rdata в рабочий набор.
 */
static bool read_remote_string(HANDLE hProc, uintptr_t remoteAddr, char* outBuf, size_t maxLen, ReadStats* stats) {
    if (!remoteAddr || !outBuf || maxLen == 0) return false;
    outBuf[0] = '\0';

    size_t toRead = (maxLen < 0x100) ? maxLen : 0xFF;
    SIZE_T bytesRead = 0;
    stats->totalRpmCalls++;

    if (ReadProcessMemory(hProc, (LPCVOID)remoteAddr, outBuf, toRead, &bytesRead) && bytesRead > 0) {
        stats->totalBytesRead += bytesRead;
        outBuf[bytesRead < maxLen ? bytesRead : maxLen - 1] = '\0';
        return true;
    }

    /* Fallback побайтово, если попали на границу страницы */
    for (size_t i = 0; i < maxLen - 1; ++i) {
        char c = 0;
        stats->totalRpmCalls++;
        if (!ReadProcessMemory(hProc, (LPCVOID)(remoteAddr + i), &c, 1, NULL)) {
            if (i > 0) {
                outBuf[i] = '\0';
                return true;
            }
            return false;
        }
        stats->totalBytesRead++;
        outBuf[i] = c;
        if (c == '\0') return true;
    }
    outBuf[maxLen - 1] = '\0';
    return true;
}

static uintptr_t get_module_base(DWORD pid, const char* modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32First(hSnap, &me)) {
        do {
            if (_stricmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return base;
}

static uint32_t find_export_rva(HANDLE hProc, uintptr_t modBase, const char* exportName, ReadStats* stats) {
    IMAGE_DOS_HEADER dos;
    stats->totalRpmCalls++;
    if (!ReadProcessMemory(hProc, (LPCVOID)modBase, &dos, sizeof(dos), NULL)) return 0;
    stats->totalBytesRead += sizeof(dos);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt;
    stats->totalRpmCalls++;
    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + dos.e_lfanew), &nt, sizeof(nt), NULL)) return 0;
    stats->totalBytesRead += sizeof(nt);
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0) return 0;

    IMAGE_EXPORT_DIRECTORY exp;
    stats->totalRpmCalls++;
    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + expDir.VirtualAddress), &exp, sizeof(exp), NULL)) return 0;
    stats->totalBytesRead += sizeof(exp);

    uint32_t numNames = exp.NumberOfNames;
    if (numNames == 0) return 0;

    uint32_t* nameRvas = (uint32_t*)malloc(numNames * sizeof(uint32_t));
    uint16_t* ordinals = (uint16_t*)malloc(numNames * sizeof(uint16_t));
    if (!nameRvas || !ordinals) {
        free(nameRvas);
        free(ordinals);
        return 0;
    }

    stats->totalRpmCalls += 2;
    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + exp.AddressOfNames), nameRvas, numNames * sizeof(uint32_t), NULL) ||
        !ReadProcessMemory(hProc, (LPCVOID)(modBase + exp.AddressOfNameOrdinals), ordinals, numNames * sizeof(uint16_t), NULL)) {
        free(nameRvas);
        free(ordinals);
        return 0;
    }
    stats->totalBytesRead += (numNames * sizeof(uint32_t)) + (numNames * sizeof(uint16_t));

    uint32_t foundRva = 0;
    char curName[128];
    for (uint32_t i = 0; i < numNames; ++i) {
        uintptr_t nameAddr = modBase + nameRvas[i];
        if (read_remote_string(hProc, nameAddr, curName, sizeof(curName), stats)) {
            if (strcmp(curName, exportName) == 0) {
                uint16_t ord = ordinals[i];
                uintptr_t funcAddr = modBase + exp.AddressOfFunctions + ord * sizeof(uint32_t);
                uint32_t rva = 0;
                stats->totalRpmCalls++;
                if (ReadProcessMemory(hProc, (LPCVOID)funcAddr, &rva, sizeof(rva), NULL)) {
                    stats->totalBytesRead += sizeof(rva);
                    foundRva = rva;
                }
                break;
            }
        }
    }

    free(nameRvas);
    free(ordinals);
    return foundRva;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Использование: %s <pid>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)strtoul(argv[1], NULL, 0);
    enable_debug_privilege();

    ReadStats stats = {0};

    LARGE_INTEGER freq, startTime, endTime;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&startTime);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("[-] Не удалось открыть процесс PID=%lu (код ошибки: %lu)\n", pid, GetLastError());
        return 1;
    }

    uintptr_t jvmBase = get_module_base(pid, "jvm.dll");
    if (!jvmBase) {
        printf("[-] Модуль jvm.dll не найден в процессе %lu!\n", pid);
        CloseHandle(hProc);
        return 1;
    }

    /* Шаг 1: перебор экспортов и поиск gHotSpotVMStructs */
    uint32_t rva = find_export_rva(hProc, jvmBase, "gHotSpotVMStructs", &stats);
    if (!rva) {
        printf("[-] Экспорт 'gHotSpotVMStructs' не найден!\n");
        CloseHandle(hProc);
        return 1;
    }

    /* Шаг 2: чтение указателя на таблицу */
    uintptr_t exportAddr = jvmBase + rva;
    uint64_t tablePtr = 0;
    stats.totalRpmCalls++;
    if (!ReadProcessMemory(hProc, (LPCVOID)exportAddr, &tablePtr, sizeof(tablePtr), NULL) || !tablePtr) {
        printf("[-] Не удалось прочитать указатель tablePtr по адресу 0x%llX\n", (unsigned long long)exportAddr);
        CloseHandle(hProc);
        return 1;
    }
    stats.totalBytesRead += sizeof(tablePtr);

    /* Шаг 3: буфер 0xBB80 (48000 байт = 1000 записей VMStructEntry) */
    VMStructEntry* chunkBuffer = (VMStructEntry*)malloc(CHUNK_BUFFER_SIZE);
    if (!chunkBuffer) {
        printf("[-] Ошибка выделения памяти под буфер 0xBB80!\n");
        CloseHandle(hProc);
        return 1;
    }

    uintptr_t curChunkRemoteAddr = (uintptr_t)tablePtr;
    bool reachedEnd = false;

    /* Локальный буфер 0x200 (512 байт) под C-строки */
    char strBuf[LOCAL_STR_BUFFER_SIZE];

    /* Полный обход всех записей и чтение всех имен */
    while (!reachedEnd) {
        SIZE_T bytesRead = 0;
        stats.totalRpmCalls++;
        if (!ReadProcessMemory(hProc, (LPCVOID)curChunkRemoteAddr, chunkBuffer, CHUNK_BUFFER_SIZE, &bytesRead) || bytesRead == 0) {
            break;
        }
        stats.totalBytesRead += bytesRead;

        uint32_t entriesInChunk = (uint32_t)(bytesRead / VMSTRUCT_ENTRY_SIZE);
        if (entriesInChunk == 0) break;

        for (uint32_t i = 0; i < entriesInChunk; ++i) {
            VMStructEntry* e = &chunkBuffer[i];

            /* Конец таблицы HotSpot: entry.typeName == 0 */
            if (!e->typeName) {
                reachedEnd = true;
                break;
            }

            stats.totalEntries++;

            /* Читаем typeName (до 0xFF байт в буфер 0x200) */
            if (read_remote_string(hProc, e->typeName, strBuf, sizeof(strBuf), &stats)) {
                stats.totalTypeNames++;
            }

            /* Читаем fieldName (до 0xFF байт в буфер 0x200) */
            if (e->fieldName) {
                if (read_remote_string(hProc, e->fieldName, strBuf, sizeof(strBuf), &stats)) {
                    stats.totalFieldNames++;
                }
            }

            /* Читаем typeString (до 0xFF байт в буфер 0x200) */
            if (e->typeString) {
                if (read_remote_string(hProc, e->typeString, strBuf, sizeof(strBuf), &stats)) {
                    stats.totalTypeStrings++;
                }
            }
        }

        curChunkRemoteAddr += (entriesInChunk * VMSTRUCT_ENTRY_SIZE);

        if (bytesRead < CHUNK_BUFFER_SIZE) {
            break;
        }
    }

    QueryPerformanceCounter(&endTime);
    double elapsedMs = (double)(endTime.QuadPart - startTime.QuadPart) * 1000.0 / (double)freq.QuadPart;

    printf("[+] Успешно выполнено external чтение gHotSpotVMStructs:\n");
    printf("    PID процесса           : %lu\n", pid);
    printf("    База jvm.dll           : 0x%llX\n", (unsigned long long)jvmBase);
    printf("    Экспорт gHotSpot... RVA: 0x%X\n", rva);
    printf("    Указатель на таблицу   : 0x%llX\n", (unsigned long long)tablePtr);
    printf("    --------------------------------------------------\n");
    printf("    Прочитано структур     : %llu\n", (unsigned long long)stats.totalEntries);
    printf("    Прочитано typeName     : %llu строк\n", (unsigned long long)stats.totalTypeNames);
    printf("    Прочитано fieldName    : %llu строк\n", (unsigned long long)stats.totalFieldNames);
    printf("    Прочитано typeString   : %llu строк\n", (unsigned long long)stats.totalTypeStrings);
    printf("    Всего прочитано строк  : %llu\n", (unsigned long long)(stats.totalTypeNames + stats.totalFieldNames + stats.totalTypeStrings));
    printf("    Вызовов RPM            : %llu\n", (unsigned long long)stats.totalRpmCalls);
    printf("    Всего прочитано байт   : %llu байт (%.2f КБ)\n", (unsigned long long)stats.totalBytesRead, (double)stats.totalBytesRead / 1024.0);
    printf("    Время выполнения       : %.2f мс\n", elapsedMs);

    free(chunkBuffer);
    CloseHandle(hProc);
    return 0;
}
