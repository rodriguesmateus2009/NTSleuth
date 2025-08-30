@echo off
setlocal enabledelayedexpansion

:: NTSleuth CI Build Script
:: Usage: build-ci.bat [x64|x86|ARM64] [Debug|Release]

:: Set default values
set ARCH=%1
set CONFIG=%2
if "%ARCH%"=="" set ARCH=x64
if "%CONFIG%"=="" set CONFIG=Release

:: Validate architecture
if /I "%ARCH%"=="x64" (
    set CMAKE_ARCH=x64
    set OUTPUT_NAME=ntsleuth-x64.exe
) else if /I "%ARCH%"=="x86" (
    set CMAKE_ARCH=Win32
    set OUTPUT_NAME=ntsleuth-x86.exe
) else if /I "%ARCH%"=="ARM64" (
    set CMAKE_ARCH=ARM64
    set OUTPUT_NAME=ntsleuth-arm64.exe
) else (
    echo [ERROR] Invalid architecture: %ARCH%
    echo Usage: build-ci.bat [x64^|x86^|ARM64] [Debug^|Release]
    exit /b 1
)

:: Validate configuration
if /I not "%CONFIG%"=="Debug" if /I not "%CONFIG%"=="Release" (
    echo [ERROR] Invalid configuration: %CONFIG%
    echo Usage: build-ci.bat [x64^|x86^|ARM64] [Debug^|Release]
    exit /b 1
)

echo ========================================
echo  NTSleuth CI Build
echo ========================================
echo Architecture: %ARCH% (%CMAKE_ARCH%)
echo Configuration: %CONFIG%
echo Output: %OUTPUT_NAME%
echo ========================================
echo.

:: Check for CMake
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] CMake not found in PATH
    echo Please install CMake from https://cmake.org/
    exit /b 1
)

:: Check for Visual Studio
where msbuild >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] MSBuild not found in PATH
    echo Attempting to locate Visual Studio...
    
    :: Try VS 2022
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
        set "PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin;%PATH%"
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
        set "PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin;%PATH%"
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
        set "PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin;%PATH%"
    ) else (
        echo [ERROR] Visual Studio 2022 not found
        exit /b 1
    )
)

:: Clean build directory
echo [*] Cleaning build directory...
if exist build (
    rmdir /s /q build 2>nul
    if exist build (
        echo [WARNING] Could not remove build directory completely
        echo Some files may be in use
    )
)

:: Create build directory
echo [*] Creating build directory...
mkdir build
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create build directory
    exit /b 1
)

cd build

:: Configure with CMake
echo [*] Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -A %CMAKE_ARCH% -DCMAKE_BUILD_TYPE=%CONFIG%
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed
    cd ..
    exit /b 1
)

:: Build the project
echo [*] Building NTSleuth...
cmake --build . --config %CONFIG% --parallel
if %errorlevel% neq 0 (
    echo [ERROR] Build failed
    cd ..
    exit /b 1
)

cd ..

:: Check if executable was created
if exist ntsleuth.exe (
    echo.
    echo ========================================
    echo  BUILD SUCCESSFUL
    echo ========================================
    echo Output: ntsleuth.exe
    
    :: Rename for architecture-specific output
    if not "%OUTPUT_NAME%"=="ntsleuth.exe" (
        copy /Y ntsleuth.exe %OUTPUT_NAME% >nul
        if exist %OUTPUT_NAME% (
            echo Architecture build: %OUTPUT_NAME%
        )
    )
    
    :: Display file info
    for %%F in (ntsleuth.exe) do (
        echo Size: %%~zF bytes
        echo Date: %%~tF
    )
    echo ========================================
    
    exit /b 0
) else (
    echo.
    echo ========================================
    echo  BUILD FAILED
    echo ========================================
    echo Executable not found
    exit /b 1
)