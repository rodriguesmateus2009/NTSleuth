@echo off
setlocal enabledelayedexpansion

echo ============================================
echo NtSleuth - Build Script
echo ============================================
echo.

:: Check for Visual Studio
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Visual Studio compiler not found in PATH
    echo.
    echo Please run this script from:
    echo   - Developer Command Prompt for Visual Studio
    echo   - Or run 'vcvarsall.bat x64' first
    echo.
    pause
    exit /b 1
)

:: Check for CMake
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] CMake not found in PATH
    echo.
    echo Please install CMake from: https://cmake.org/download/
    echo And ensure it's added to your PATH
    echo.
    pause
    exit /b 1
)

:: Detect architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set ARCH=x64
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set ARCH=ARM64
) else (
    set ARCH=x86
)

echo [INFO] Detected architecture: %ARCH%

:: Parse command line arguments
set BUILD_TYPE=Release
set CLEAN_BUILD=0
set RUN_AFTER=0

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="debug" set BUILD_TYPE=Debug
if /i "%~1"=="release" set BUILD_TYPE=Release
if /i "%~1"=="clean" set CLEAN_BUILD=1
if /i "%~1"=="run" set RUN_AFTER=1
if /i "%~1"=="x64" set ARCH=x64
if /i "%~1"=="arm64" set ARCH=ARM64
if /i "%~1"=="x86" set ARCH=Win32
shift
goto :parse_args
:args_done

echo [INFO] Build configuration: %BUILD_TYPE%
echo [INFO] Target architecture: %ARCH%
echo.

:: Clean if requested
if %CLEAN_BUILD%==1 (
    echo [INFO] Cleaning previous build...
    if exist build rmdir /s /q build
    if exist cache rmdir /s /q cache
    if exist output rmdir /s /q output
    if exist ntsleuth.exe del /q ntsleuth.exe
    if exist ntsleuth.pdb del /q ntsleuth.pdb
    echo [INFO] Clean complete
    echo.
)

:: Create build directory
if not exist build (
    echo [INFO] Creating build directory...
    mkdir build
)

cd build

:: Detect Visual Studio version
set VS_VERSION=
set CMAKE_GENERATOR=

:: Try VS 2022
if exist "%ProgramFiles%\Microsoft Visual Studio\2022" (
    set VS_VERSION=2022
    set CMAKE_GENERATOR=Visual Studio 17 2022
    goto :vs_found
)

:: Try VS 2019
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019" (
    set VS_VERSION=2019
    set CMAKE_GENERATOR=Visual Studio 16 2019
    goto :vs_found
)

:: Fallback to whatever CMake finds
set CMAKE_GENERATOR=Visual Studio 17 2022
echo [WARNING] Could not detect Visual Studio version, using default generator

:vs_found
if not "%VS_VERSION%"=="" (
    echo [INFO] Found Visual Studio %VS_VERSION%
)

:: Configure with CMake
echo.
echo [INFO] Configuring project with CMake...
echo [INFO] Generator: %CMAKE_GENERATOR%
echo.

cmake .. -G "%CMAKE_GENERATOR%" -A %ARCH% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] CMake configuration failed
    cd ..
    pause
    exit /b 1
)

:: Build the project
echo.
echo [INFO] Building project...
echo.

set CPU_COUNT=%NUMBER_OF_PROCESSORS%
if "%CPU_COUNT%"=="" set CPU_COUNT=4

cmake --build . --config %BUILD_TYPE% --parallel %CPU_COUNT%
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed
    cd ..
    pause
    exit /b 1
)

:: Success message
echo.
echo ============================================
echo BUILD SUCCESSFUL!
echo ============================================
echo.
echo Executable location:
echo   ntsleuth.exe (in project root)
echo.

cd ..

:: Run if requested
if %RUN_AFTER%==1 (
    echo [INFO] Running NtSleuth...
    echo.
    ntsleuth.exe --help
    echo.
)

echo Usage examples:
echo   ntsleuth.exe              - Extract all syscalls
echo   ntsleuth.exe --auto-params - With automated parameter resolution
echo   ntsleuth.exe -o output    - Save to 'output' directory
echo   ntsleuth.exe --help       - Show all options
echo.
echo To rebuild: build.bat clean
echo To build debug: build.bat debug
echo To build and run: build.bat run
echo.
pause