// mcres — резидентность страниц чужого процесса, без влияния на неё.
//
// Правило этой программы: ни одного байта из памяти цели не читается.
// Используются только запросы к ядру:
//     VirtualQueryEx          — карта регионов
//     QueryWorkingSetEx       — резидентна ли страница
//     GetMappedFileNameW      — имя файла проекции (объект секции, не страницы)
//     GetProcessMemoryInfo    — счётчики процесса
// Ни ReadProcessMemory, ни NtReadVirtualMemory, ни проекций памяти цели.
// Поэтому замер не поднимает ни одной страницы в рабочее множество.

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

// ---------------------------------------------------------------------------
// Описание блока рабочего множества. Объявляем сами: в разных заголовках
// mingw оно либо отсутствует, либо прячется за версионными макросами.
// ---------------------------------------------------------------------------
typedef union MCRES_WS_BLOCK {
    ULONG_PTR Flags;
    struct {
        ULONG_PTR Valid : 1;
        ULONG_PTR ShareCount : 3;
        ULONG_PTR Win32Protection : 11;
        ULONG_PTR Shared : 1;
        ULONG_PTR Node : 6;
        ULONG_PTR Locked : 1;
        ULONG_PTR LargePage : 1;
        ULONG_PTR Reserved : 7;
        ULONG_PTR Bad : 1;
        ULONG_PTR ReservedUlong : 32;
    } b;
} MCRES_WS_BLOCK;

typedef struct MCRES_WS_INFO {
    PVOID          VirtualAddress;
    MCRES_WS_BLOCK VirtualAttributes;
} MCRES_WS_INFO;

typedef BOOL (WINAPI *PFN_QueryWorkingSetEx)(HANDLE, PVOID, DWORD);

static const SIZE_T PAGE = 4096;

// ---------------------------------------------------------------------------
// Мелкие помощники
// ---------------------------------------------------------------------------
static void fail(const char* what) {
    std::fprintf(stderr, "ошибка: %s (код %lu)\n", what, GetLastError());
    std::exit(2);
}

static std::string human(unsigned long long bytes) {
    char buf[64];
    const char* u[] = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
    double v = (double)bytes; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    std::snprintf(buf, sizeof buf, (i == 0 ? "%.0f %s" : "%.2f %s"), v, u[i]);
    return buf;
}

static std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}


// Выравнивание по ЧИСЛУ СИМВОЛОВ, а не байтов: в UTF-8 кириллица занимает
// два байта, и printf("%-22s") на ней ломает колонки.
static std::string padu(const std::string& s, int cols, bool left = true) {
    int w = 0;
    for (unsigned char c : s) if ((c & 0xC0) != 0x80) ++w;
    int add = cols - w; if (add < 0) add = 0;
    return left ? s + std::string((size_t)add, ' ') : std::string((size_t)add, ' ') + s;
}

static const char* prot_name(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "R--";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_WRITECOPY:         return "RWc";
        case PAGE_EXECUTE:           return "--X";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RXc";
        default:                     return "?..";
    }
}

// Таблица «\Device\HarddiskVolumeN» -> «C:» строится один раз, запросами к ядру.
static std::map<std::wstring, std::wstring> g_devmap;

static void build_devmap() {
    wchar_t drives[512] = {};
    DWORD n = GetLogicalDriveStringsW(511, drives);
    for (wchar_t* d = drives; *d && (d - drives) < (ptrdiff_t)n; d += wcslen(d) + 1) {
        wchar_t letter[3] = { d[0], L':', 0 };
        wchar_t target[MAX_PATH] = {};
        if (QueryDosDeviceW(letter, target, MAX_PATH))
            g_devmap[target] = letter;
    }
}

static std::wstring dos_path(const std::wstring& nt) {
    for (auto& kv : g_devmap) {
        if (nt.size() > kv.first.size() &&
            _wcsnicmp(nt.c_str(), kv.first.c_str(), kv.first.size()) == 0 &&
            nt[kv.first.size()] == L'\\')
            return kv.second + nt.substr(kv.first.size());
    }
    return nt;
}

static std::wstring base_name(const std::wstring& p) {
    size_t i = p.find_last_of(L"\\/");
    return (i == std::wstring::npos) ? p : p.substr(i + 1);
}

// ---------------------------------------------------------------------------
// Поиск процесса
// ---------------------------------------------------------------------------
static DWORD pid_by_name(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof pe;
    DWORD found = 0, count = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { found = pe.th32ProcessID; ++count; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (count > 1)
        std::fprintf(stderr, "предупреждение: процессов с таким именем %lu, взят последний (%lu)\n", count, found);
    return found;
}

// ---------------------------------------------------------------------------
// Регион памяти с посчитанной резидентностью
// ---------------------------------------------------------------------------
struct Region {
    ULONG_PTR    base = 0;
    ULONG_PTR    alloc = 0;
    SIZE_T       size = 0;
    DWORD        prot = 0;
    DWORD        type = 0;          // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    SIZE_T       pages = 0;
    SIZE_T       resident = 0;
    SIZE_T       shared = 0;
    SIZE_T       locked = 0;
    SIZE_T       largepg = 0;
    std::wstring file;              // для IMAGE/MAPPED
};

struct Totals {
    SIZE_T pages = 0, resident = 0;
    void add(const Region& r) { pages += r.pages; resident += r.resident; }
    double pct() const { return pages ? 100.0 * (double)resident / (double)pages : 0.0; }
};

// Запрос резидентности пачками: своя память, цели не касаемся.
static bool query_residency(HANDLE h, PFN_QueryWorkingSetEx fn, Region& r) {
    const SIZE_T CHUNK = 64 * 1024;                   // 64К страниц = 1 МБ своей памяти
    std::vector<MCRES_WS_INFO> buf;
    buf.reserve(std::min(r.pages, CHUNK));
    SIZE_T done = 0;
    while (done < r.pages) {
        SIZE_T n = std::min(CHUNK, r.pages - done);
        buf.assign(n, MCRES_WS_INFO{});
        for (SIZE_T i = 0; i < n; ++i)
            buf[i].VirtualAddress = (PVOID)(r.base + (done + i) * PAGE);
        if (!fn(h, buf.data(), (DWORD)(n * sizeof(MCRES_WS_INFO))))
            return false;
        for (SIZE_T i = 0; i < n; ++i) {
            const MCRES_WS_BLOCK& b = buf[i].VirtualAttributes;
            if (b.b.Valid) {
                ++r.resident;
                if (b.b.Shared)    ++r.shared;
                if (b.b.Locked)    ++r.locked;
                if (b.b.LargePage) ++r.largepg;
            }
        }
        done += n;
    }
    return true;
}

static std::vector<Region> enumerate(HANDLE h, PFN_QueryWorkingSetEx fn) {
    std::vector<Region> out;
    MEMORY_BASIC_INFORMATION mbi{};
    ULONG_PTR addr = 0;
    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof mbi) == sizeof mbi) {
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;                       // защита от зацикливания
        if (mbi.State == MEM_COMMIT) {
            Region r;
            r.base  = (ULONG_PTR)mbi.BaseAddress;
            r.alloc = (ULONG_PTR)mbi.AllocationBase;
            r.size  = mbi.RegionSize;
            r.prot  = mbi.Protect;
            r.type  = mbi.Type;
            r.pages = mbi.RegionSize / PAGE;
            if (mbi.Type != MEM_PRIVATE) {
                wchar_t nm[MAX_PATH] = {};
                if (GetMappedFileNameW(h, mbi.BaseAddress, nm, MAX_PATH))
                    r.file = dos_path(nm);
            }
            if (r.pages && query_residency(h, fn, r))
                out.push_back(std::move(r));
        }
        addr = next;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Канарейка по карте структур виртуальной машины.
//
// Смысл: страницы с именами типов и полей внутри jvm.dll сама машина в работе
// не читает. Чтобы узнать, какие это страницы, библиотека разбирается НА ДИСКЕ
// (обычным чтением файла), а у цели только спрашивается резидентность этих
// страниц. Ни одного чтения памяти цели.
//
// Имя символа собирается во время работы, чтобы не лежать в exe открытой строкой.
// ---------------------------------------------------------------------------
static std::string canary_symbol() {
    static const unsigned char enc[] = { 0x0C,0x23,0x04,0x1F,0x38,0x1B,0x04,0x1F,0x3D,0x26,0x38,0x1F,0x19,0x1E,0x08,0x1F,0x18 };
    std::string s;
    for (unsigned char c : enc) s.push_back((char)(c ^ 0x6B));
    return s;
}

struct PeFile {
    std::vector<unsigned char> buf;
    ULONGLONG   imageBase = 0;
    DWORD       exportRva = 0, exportSize = 0;
    std::vector<std::pair<DWORD, DWORD>> sections;     // rva, size
    std::vector<std::pair<DWORD, DWORD>> raw;          // rva -> raw offset

    bool load(const std::wstring& path) {
        HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(f, &sz);
        if (sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)256 * 1024 * 1024) { CloseHandle(f); return false; }
        buf.resize((size_t)sz.QuadPart);
        DWORD got = 0, off = 0;
        while (off < buf.size() && ReadFile(f, buf.data() + off, (DWORD)std::min<size_t>(1 << 20, buf.size() - off), &got, nullptr) && got)
            off += got;
        CloseHandle(f);
        return parse();
    }

    template <class T> bool at(size_t off, T& v) const {
        if (off + sizeof(T) > buf.size()) return false;
        std::memcpy(&v, buf.data() + off, sizeof(T));
        return true;
    }

    bool parse() {
        WORD mz = 0; DWORD lfanew = 0;
        if (!at(0, mz) || mz != 0x5A4D) return false;
        if (!at(0x3C, lfanew)) return false;
        DWORD sig = 0;
        if (!at(lfanew, sig) || sig != 0x00004550) return false;
        size_t coff = lfanew + 4;
        WORD nsec = 0, optsz = 0, magic = 0;
        if (!at(coff + 2, nsec) || !at(coff + 16, optsz)) return false;
        size_t opt = coff + 20;
        if (!at(opt, magic) || magic != 0x20B) return false;             // только PE32+
        if (!at(opt + 24, imageBase)) return false;
        if (!at(opt + 112, exportRva) || !at(opt + 116, exportSize)) return false;
        size_t so = opt + optsz;
        for (WORD i = 0; i < nsec; ++i) {
            DWORD vs = 0, va = 0, rs = 0, pr = 0;
            size_t s = so + (size_t)i * 40;
            if (!at(s + 8, vs) || !at(s + 12, va) || !at(s + 16, rs) || !at(s + 20, pr)) return false;
            sections.emplace_back(va, vs ? vs : rs);
            raw.emplace_back(va, pr);
        }
        return true;
    }

    // RVA -> смещение в файле
    long long to_off(DWORD rva) const {
        for (size_t i = 0; i < sections.size(); ++i) {
            DWORD va = sections[i].first, vs = sections[i].second;
            if (rva >= va && rva < va + vs) return (long long)raw[i].second + (rva - va);
        }
        return -1;
    }

    DWORD export_rva(const std::string& name) const {
        if (!exportRva) return 0;
        long long e = to_off(exportRva);
        if (e < 0) return 0;
        DWORD nfunc = 0, nname = 0, afunc = 0, aname = 0, aord = 0;
        if (!at((size_t)e + 20, nfunc) || !at((size_t)e + 24, nname) ||
            !at((size_t)e + 28, afunc) || !at((size_t)e + 32, aname) || !at((size_t)e + 36, aord))
            return 0;
        long long of = to_off(afunc), on = to_off(aname), oo = to_off(aord);
        if (of < 0 || on < 0 || oo < 0) return 0;
        for (DWORD i = 0; i < nname; ++i) {
            DWORD nr = 0; WORD ord = 0;
            if (!at((size_t)on + (size_t)i * 4, nr) || !at((size_t)oo + (size_t)i * 2, ord)) break;
            long long os = to_off(nr);
            if (os < 0 || (size_t)os >= buf.size()) continue;
            const char* s = (const char*)buf.data() + os;
            if (name == s) {
                DWORD fr = 0;
                if (ord < nfunc && at((size_t)of + (size_t)ord * 4, fr)) return fr;
                return 0;
            }
        }
        return 0;
    }
};

struct CanaryResult {
    bool   ok = false;
    std::string why;
    DWORD  stride = 0;
    DWORD  entries = 0;
    std::vector<DWORD> pages;        // RVA страниц с именами
};

// Собрать набор страниц, на которых лежат имена типов и полей.
static CanaryResult canary_pages(const std::wstring& jvmPath) {
    CanaryResult cr;
    PeFile pe;
    if (!pe.load(jvmPath)) { cr.why = "библиотеку не удалось прочитать с диска"; return cr; }

    DWORD symRva = pe.export_rva(canary_symbol());
    if (!symRva) { cr.why = "нужный символ в таблице экспорта не найден"; return cr; }

    long long symOff = pe.to_off(symRva);
    if (symOff < 0) { cr.why = "символ вне секций файла"; return cr; }

    ULONGLONG tableVa = 0;
    if (!pe.at((size_t)symOff, tableVa) || tableVa <= pe.imageBase) {
        cr.why = "начальное значение указателя в файле непригодно"; return cr;
    }
    DWORD tableRva = (DWORD)(tableVa - pe.imageBase);

    // Шаг записи выводим по месту: берём тот, при котором первые записи дают
    // печатаемые имена внутри файла.
    const DWORD tries[] = { 48, 56, 40, 64, 32 };
    for (DWORD stride : tries) {
        long long off = pe.to_off(tableRva);
        if (off < 0) continue;
        int good = 0;
        for (int i = 0; i < 8; ++i) {
            ULONGLONG p = 0;
            if (!pe.at((size_t)off + (size_t)i * stride, p)) break;
            if (p <= pe.imageBase) break;
            long long so = pe.to_off((DWORD)(p - pe.imageBase));
            if (so < 0 || (size_t)so >= pe.buf.size()) break;
            const unsigned char* s = pe.buf.data() + so;
            int len = 0;
            while (len < 64 && s[len] >= 0x20 && s[len] < 0x7F) ++len;
            if (len >= 3 && s[len] == 0) ++good;
        }
        if (good >= 6) { cr.stride = stride; break; }
    }
    if (!cr.stride) { cr.why = "шаг записи таблицы определить не удалось"; return cr; }

    long long off = pe.to_off(tableRva);
    std::vector<DWORD> pg;
    for (DWORD i = 0; i < 20000; ++i) {
        size_t rec = (size_t)off + (size_t)i * cr.stride;
        ULONGLONG p1 = 0, p2 = 0, p3 = 0;
        if (!pe.at(rec, p1)) break;
        if (p1 == 0) break;                            // конец таблицы
        pe.at(rec + 8, p2);
        pe.at(rec + 16, p3);
        ++cr.entries;
        for (ULONGLONG p : { p1, p2, p3 }) {
            if (p <= pe.imageBase) continue;
            DWORD r = (DWORD)(p - pe.imageBase);
            if (pe.to_off(r) < 0) continue;
            pg.push_back(r & ~(DWORD)(PAGE - 1));
        }
    }
    std::sort(pg.begin(), pg.end());
    pg.erase(std::unique(pg.begin(), pg.end()), pg.end());
    cr.pages = std::move(pg);
    cr.ok = !cr.pages.empty();
    if (!cr.ok) cr.why = "страниц с именами не найдено";
    return cr;
}

// ---------------------------------------------------------------------------
// Вывод
// ---------------------------------------------------------------------------
struct Opts {
    DWORD pid = 0;
    std::wstring name;
    bool all = false, onlyMod = false, onlyPriv = false, brief = false;
    bool canary = false, twice = false;
    int  top = 0;
    std::string json;
    std::wstring probe;
};

static void usage() {
    std::printf(
        "mcres — резидентность страниц памяти процесса\n"
        "\n"
        "  mcres <pid | имя.exe> [опции]\n"
        "\n"
        "  -a            показать все регионы, а не только сводку и модули\n"
        "  -m            только образы модулей\n"
        "  -p            только приватная память\n"
        "  -n N          N регионов с наибольшим числом резидентных страниц\n"
        "  -c            добавить замер по карте структур виртуальной машины\n"
        "  -2            повторить замер ещё раз и показать разницу\n"
        "  -q            только сводка\n"
        "  -j <файл>     записать результат в JSON\n"
        "\n"
        "Память цели не читается: только VirtualQueryEx, QueryWorkingSetEx,\n"
        "GetMappedFileNameW и счётчики процесса. Замер не поднимает страницы.\n");
}

struct Snapshot {
    DWORD  faults = 0;
    SIZE_T ws = 0, peak = 0;
};

static Snapshot take_counters(HANDLE h) {
    Snapshot s;
    PROCESS_MEMORY_COUNTERS pmc{}; pmc.cb = sizeof pmc;
    if (GetProcessMemoryInfo(h, &pmc, sizeof pmc)) {
        s.faults = pmc.PageFaultCount;
        s.ws     = pmc.WorkingSetSize;
        s.peak   = pmc.PeakWorkingSetSize;
    }
    return s;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) { usage(); return 1; }

    Opts o;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"-a") o.all = true;
        else if (a == L"-m") o.onlyMod = true;
        else if (a == L"-p") o.onlyPriv = true;
        else if (a == L"-q") o.brief = true;
        else if (a == L"-c") o.canary = true;
        else if (a == L"-2") o.twice = true;
        else if (a == L"-n" && i + 1 < argc) o.top = _wtoi(argv[++i]);
        else if (a == L"-j" && i + 1 < argc) o.json = narrow(argv[++i]);
        else if (a == L"--probe" && i + 1 < argc) o.probe = argv[++i];
        else if (a == L"-h" || a == L"--help") { usage(); return 0; }
        else if (!a.empty() && iswdigit(a[0])) o.pid = (DWORD)_wtoi(a.c_str());
        else o.name = a;
    }
    if (!o.probe.empty()) {
        CanaryResult t = canary_pages(o.probe);
        std::printf("РАЗБОР БИБЛИОТЕКИ С ДИСКА\n  файл                 : %s\n", narrow(o.probe).c_str());
        if (!t.ok) { std::printf("  результат            : %s\n", t.why.c_str()); return 1; }
        std::printf("  записей в таблице    : %lu (шаг %lu байт)\n", t.entries, t.stride);
        std::printf("  страниц с именами    : %zu\n", t.pages.size());
        std::printf("  первые страницы      :");
        for (size_t i = 0; i < t.pages.size() && i < 8; ++i) std::printf(" +0x%X", t.pages[i]);
        std::printf("\n");
        return 0;
    }
    if (!o.pid && !o.name.empty()) o.pid = pid_by_name(o.name.c_str());
    if (!o.pid) { std::fprintf(stderr, "процесс не найден\n"); return 1; }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    PFN_QueryWorkingSetEx qws = (PFN_QueryWorkingSetEx)GetProcAddress(k32, "K32QueryWorkingSetEx");
    if (!qws) {
        HMODULE ps = LoadLibraryW(L"psapi.dll");
        if (ps) qws = (PFN_QueryWorkingSetEx)GetProcAddress(ps, "QueryWorkingSetEx");
    }
    if (!qws) fail("QueryWorkingSetEx недоступна");

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, o.pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, o.pid);
    if (!h) fail("не удалось открыть процесс (нужны права администратора)");

    build_devmap();

    Snapshot before = take_counters(h);
    LARGE_INTEGER f0{}, t0{}, t1{};
    QueryPerformanceFrequency(&f0); QueryPerformanceCounter(&t0);

    std::vector<Region> regs = enumerate(h, qws);

    QueryPerformanceCounter(&t1);
    Snapshot after = take_counters(h);
    double secs = (double)(t1.QuadPart - t0.QuadPart) / (double)f0.QuadPart;

    // ---- сводка по типам
    Totals tImg, tMap, tPriv, tAll;
    for (auto& r : regs) {
        tAll.add(r);
        if (r.type == MEM_IMAGE)       tImg.add(r);
        else if (r.type == MEM_MAPPED) tMap.add(r);
        else                           tPriv.add(r);
    }

    // ---- модули: группировка по файлу
    struct Mod { SIZE_T pages = 0, resident = 0; ULONG_PTR base = ~(ULONG_PTR)0; };
    std::map<std::wstring, Mod> mods;
    for (auto& r : regs) {
        if (r.type != MEM_IMAGE || r.file.empty()) continue;
        Mod& m = mods[r.file];
        m.pages += r.pages; m.resident += r.resident;
        m.base = std::min(m.base, r.alloc ? r.alloc : r.base);
    }

    wchar_t selfName[MAX_PATH] = {};
    {   // имя образа процесса — через объект секции, без чтения памяти
        for (auto& r : regs)
            if (r.type == MEM_IMAGE && !r.file.empty() &&
                base_name(r.file).find(L".exe") != std::wstring::npos) {
                wcsncpy(selfName, r.file.c_str(), MAX_PATH - 1); break;
            }
    }

    std::printf("ПРОЦЕСС %lu  %s\n", o.pid, narrow(base_name(selfName)).c_str());
    if (selfName[0]) std::printf("  образ                : %s\n", narrow(selfName).c_str());
    std::printf("  занято регионов      : %zu\n", regs.size());
    std::printf("  замер занял          : %.2f с\n\n", secs);

    std::printf("РЕЗИДЕНТНОСТЬ\n");
    std::printf("  %s %s %s %s\n", padu("", 22).c_str(), padu("страниц", 12, false).c_str(),
                padu("резидентно", 12, false).c_str(), padu("доля", 8, false).c_str());
    auto line = [](const char* t, const Totals& x) {
        std::printf("  %s %12zu %12zu %7.1f%%\n", padu(t, 22).c_str(), x.pages, x.resident, x.pct());
    };
    line("образы библиотек", tImg);
    line("проекции файлов",  tMap);
    line("приватная память", tPriv);
    line("ВСЕГО",            tAll);
    std::printf("  %s %12s %12s\n", padu("в байтах", 22).c_str(), human((unsigned long long)tAll.pages * PAGE).c_str(),
                human((unsigned long long)tAll.resident * PAGE).c_str());
    std::printf("\n");

    std::printf("САМОПРОВЕРКА: ЧТО ИЗМЕНИЛОСЬ У ЦЕЛИ ЗА ЗАМЕР\n");
    std::printf("  ошибок страниц       : %lu -> %lu  (%+ld)\n",
                before.faults, after.faults, (long)after.faults - (long)before.faults);
    std::printf("  рабочее множество    : %s -> %s\n",
                human(before.ws).c_str(), human(after.ws).c_str());
    std::printf("  пик рабочего мн-ва   : %s -> %s\n",
                human(before.peak).c_str(), human(after.peak).c_str());
    std::printf("  страниц прочитано нами: 0 — память цели не читается вовсе\n");
    std::printf("  (ненулевая разница — работа самого процесса, не наша)\n\n");

    // ---- модули
    if (!o.onlyPriv) {
        std::vector<std::pair<std::wstring, Mod>> ms(mods.begin(), mods.end());
        std::sort(ms.begin(), ms.end(), [](auto& a, auto& b) {
            return a.second.resident > b.second.resident;
        });
        size_t full = 0;
        for (auto& m : ms) if (m.second.pages && m.second.pages == m.second.resident) ++full;
        std::printf("МОДУЛИ: %zu, резидентны целиком: %zu\n", ms.size(), full);
        if (!o.brief) {
            std::printf("  %s %s %s %s  %s\n", padu("БАЗА", 18).c_str(), padu("страниц", 10, false).c_str(),
                        padu("резид.", 10, false).c_str(), padu("доля", 8, false).c_str(), "ФАЙЛ");
            size_t shown = 0;
            for (auto& m : ms) {
                if (o.top && (int)shown >= o.top) break;
                double p = m.second.pages ? 100.0 * (double)m.second.resident / (double)m.second.pages : 0;
                std::printf("  0x%016llX %10zu %10zu %7.1f%%  %s%s\n",
                            (unsigned long long)m.second.base, m.second.pages, m.second.resident, p,
                            narrow(base_name(m.first)).c_str(),
                            (m.second.pages == m.second.resident ? "  <- целиком" : ""));
                ++shown;
            }
        }
        std::printf("\n");
    }

    // ---- регионы
    if (o.all || o.onlyPriv || o.top) {
        std::vector<Region*> rp;
        for (auto& r : regs) {
            if (o.onlyMod  && r.type != MEM_IMAGE)   continue;
            if (o.onlyPriv && r.type != MEM_PRIVATE) continue;
            rp.push_back(&r);
        }
        if (o.top)
            std::sort(rp.begin(), rp.end(), [](Region* a, Region* b) { return a->resident > b->resident; });
        std::printf("РЕГИОНЫ%s\n", o.top ? " (по числу резидентных страниц)" : "");
        std::printf("  %s %s %s %s %s %s %s  %s\n",
                    padu("БАЗА", 18).c_str(), padu("РАЗМЕР", 10, false).c_str(),
                    padu("ТИП", 8, false).c_str(), padu("ПРАВА", 5, false).c_str(),
                    padu("страниц", 8, false).c_str(), padu("резид.", 10, false).c_str(),
                    padu("доля", 8, false).c_str(), "ФАЙЛ");
        int shown = 0;
        for (Region* r : rp) {
            if (o.top && shown >= o.top) break;
            const char* t = (r->type == MEM_IMAGE) ? "IMAGE" : (r->type == MEM_MAPPED) ? "MAPPED" : "PRIVATE";
            double p = r->pages ? 100.0 * (double)r->resident / (double)r->pages : 0;
            std::printf("  0x%016llX %10s %8s %5s %8zu %10zu %7.1f%%  %s\n",
                        (unsigned long long)r->base, human(r->size).c_str(), t, prot_name(r->prot),
                        r->pages, r->resident, p, narrow(base_name(r->file)).c_str());
            ++shown;
        }
        std::printf("\n");
    }

    // ---- канарейка
    CanaryResult cr;
    SIZE_T canResident = 0;
    if (o.canary) {
        std::wstring jvm;
        for (auto& kv : mods)
            if (_wcsicmp(base_name(kv.first).c_str(), L"jvm.dll") == 0) { jvm = kv.first; break; }
        if (jvm.empty()) {
            std::printf("КАРТА СТРУКТУР ВМ: jvm.dll в процессе нет — замер не делается\n\n");
        } else {
            ULONG_PTR jvmBase = mods[jvm].base;
            cr = canary_pages(jvm);
            if (!cr.ok) {
                std::printf("КАРТА СТРУКТУР ВМ: %s\n\n", cr.why.c_str());
            } else {
                std::vector<MCRES_WS_INFO> q(cr.pages.size());
                for (size_t i = 0; i < cr.pages.size(); ++i)
                    q[i].VirtualAddress = (PVOID)(jvmBase + cr.pages[i]);
                if (qws(h, q.data(), (DWORD)(q.size() * sizeof(MCRES_WS_INFO)))) {
                    for (auto& e : q) if (e.VirtualAttributes.b.Valid) ++canResident;
                }
                std::printf("КАРТА СТРУКТУР ВМ (страницы имён типов и полей)\n");
                std::printf("  библиотека           : %s\n", narrow(jvm).c_str());
                std::printf("  база в процессе      : 0x%016llX\n", (unsigned long long)jvmBase);
                std::printf("  записей в таблице    : %lu (шаг %lu байт)\n", cr.entries, cr.stride);
                std::printf("  страниц с именами    : %zu\n", cr.pages.size());
                std::printf("  из них резидентны    : %zu  (%.1f%%)\n",
                            canResident, cr.pages.empty() ? 0.0 :
                            100.0 * (double)canResident / (double)cr.pages.size());
                std::printf("  таблица разобрана с диска, память цели не читалась\n\n");
            }
        }
    }

    // ---- второй замер
    if (o.twice) {
        Snapshot b2 = take_counters(h);
        std::vector<Region> regs2 = enumerate(h, qws);
        Snapshot a2 = take_counters(h);
        Totals t2;
        for (auto& r : regs2) t2.add(r);
        std::printf("ПОВТОРНЫЙ ЗАМЕР\n");
        std::printf("  резидентно было      : %zu страниц (%.1f%%)\n", tAll.resident, tAll.pct());
        std::printf("  резидентно стало     : %zu страниц (%.1f%%)\n", t2.resident, t2.pct());
        std::printf("  разница              : %+lld страниц\n",
                    (long long)t2.resident - (long long)tAll.resident);
        std::printf("  ошибок страниц       : %lu -> %lu  (%+ld)\n\n",
                    b2.faults, a2.faults, (long)a2.faults - (long)b2.faults);
    }

    // ---- JSON
    if (!o.json.empty()) {
        FILE* f = std::fopen(o.json.c_str(), "wb");
        if (!f) { std::fprintf(stderr, "не удалось открыть %s\n", o.json.c_str()); }
        else {
            std::fprintf(f, "{\n  \"pid\": %lu,\n  \"image\": \"%s\",\n", o.pid,
                         narrow(base_name(selfName)).c_str());
            std::fprintf(f, "  \"elapsedSeconds\": %.3f,\n", secs);
            std::fprintf(f, "  \"totals\": {\n");
            auto jt = [&](const char* n, const Totals& x, bool last) {
                std::fprintf(f, "    \"%s\": {\"pages\": %zu, \"resident\": %zu, \"percent\": %.2f}%s\n",
                             n, x.pages, x.resident, x.pct(), last ? "" : ",");
            };
            jt("image", tImg, false); jt("mapped", tMap, false);
            jt("private", tPriv, false); jt("all", tAll, true);
            std::fprintf(f, "  },\n");
            std::fprintf(f, "  \"selfCheck\": {\"pagesReadByTool\": 0, \"faultsBefore\": %lu, \"faultsAfter\": %lu,"
                            " \"wsBefore\": %zu, \"wsAfter\": %zu, \"peakBefore\": %zu, \"peakAfter\": %zu},\n",
                         before.faults, after.faults, before.ws, after.ws, before.peak, after.peak);
            if (o.canary && cr.ok)
                std::fprintf(f, "  \"vmMapPages\": {\"entries\": %lu, \"stride\": %lu, \"pages\": %zu, \"resident\": %zu},\n",
                             cr.entries, cr.stride, cr.pages.size(), canResident);
            std::fprintf(f, "  \"modules\": [\n");
            size_t i = 0;
            for (auto& m : mods) {
                std::fprintf(f, "    {\"base\": %llu, \"pages\": %zu, \"resident\": %zu, \"file\": \"",
                             (unsigned long long)m.second.base, m.second.pages, m.second.resident);
                std::string p = narrow(m.first);
                for (char c : p) { if (c == '\\' || c == '"') std::fputc('\\', f); std::fputc(c, f); }
                std::fprintf(f, "\"}%s\n", (++i == mods.size()) ? "" : ",");
            }
            std::fprintf(f, "  ]\n}\n");
            std::fclose(f);
            std::printf("JSON записан: %s\n", o.json.c_str());
        }
    }

    CloseHandle(h);
    return 0;
}
