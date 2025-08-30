@echo off
echo ============================================
echo Windows Syscall Extractor - Clean Script
echo ============================================
echo.

echo [INFO] Cleaning build artifacts...

if exist build (
    echo [INFO] Removing build directory...
    rmdir /s /q build
)

if exist cache (
    echo [INFO] Removing cache directory...
    rmdir /s /q cache
)

if exist output (
    echo [INFO] Removing output directory...
    rmdir /s /q output
)

if exist ntsleuth.exe (
    echo [INFO] Removing executable from root...
    del /q ntsleuth.exe
)

if exist ntsleuth.pdb (
    echo [INFO] Removing debug symbols from root...
    del /q ntsleuth.pdb
)

if exist ntsleuth.ilk (
    del /q ntsleuth.ilk
)

if exist .vs (
    echo [INFO] Removing Visual Studio cache...
    rmdir /s /q .vs
)

if exist CMakeFiles (
    echo [INFO] Removing CMake cache...
    rmdir /s /q CMakeFiles
)

if exist CMakeCache.txt (
    del /q CMakeCache.txt
)

if exist *.vcxproj (
    echo [INFO] Removing generated project files...
    del /q *.vcxproj
)

if exist *.vcxproj.filters (
    del /q *.vcxproj.filters
)

if exist *.vcxproj.user (
    del /q *.vcxproj.user
)

if exist *.sln (
    del /q *.sln
)

echo.
echo [SUCCESS] Clean complete!
echo.
echo You can now run 'build.bat' for a fresh build.
echo.
pause