@echo off
echo Building FolderLocker native DLL...

g++ -shared -o folder_locker.dll -O2 -std=c++17 -Wall -static-libgcc -static-libstdc++ -static -lpthread src\folder_locker.cpp -ladvapi32

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful.
    echo DLL created: folder_locker.dll
    echo.
    echo Checking dependencies...
    objdump -p folder_locker.dll | findstr "DLL Name"
) else (
    echo.
    echo Build FAILED. Check errors above.
)