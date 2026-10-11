@echo off
rem ---------------------------------------------------------------------
rem  mcres - build to a single self-contained exe.
rem  Any one of the two toolchains is enough.
rem ---------------------------------------------------------------------
setlocal
cd /d "%~dp0"

where cl.exe >nul 2>nul
if %errorlevel%==0 (
    echo [MSVC] building...
    cl /nologo /std:c++17 /O2 /EHsc /MT /DUNICODE /D_UNICODE mcres.cpp /Fe:mcres.exe /link psapi.lib
    if errorlevel 1 goto err
    if exist mcres.obj del /q mcres.obj
    goto ok
)

where g++.exe >nul 2>nul
if %errorlevel%==0 (
    echo [g++] building...
    g++ -std=c++17 -O2 -municode -o mcres.exe mcres.cpp -lpsapi -static -static-libgcc -static-libstdc++
    if errorlevel 1 goto err
    goto ok
)

echo Neither cl.exe nor g++.exe found in PATH.
exit /b 1

:ok
echo.
echo Done: mcres.exe
echo Imports: KERNEL32 + system UCRT only (ships with Windows 10+).
exit /b 0

:err
echo Build failed.
exit /b 1
