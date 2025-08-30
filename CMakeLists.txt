cmake_minimum_required(VERSION 3.20)
project(NtSleuth VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform check
if(NOT WIN32)
    message(FATAL_ERROR "This project only builds on Windows")
endif()

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64")
        set(TARGET_ARCH "ARM64")
    else()
        set(TARGET_ARCH "x64")
    endif()
else()
    set(TARGET_ARCH "x86")
endif()

message(STATUS "Building for ${TARGET_ARCH} architecture")

# Output directories
# Place the executable in the project root directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_SOURCE_DIR})

# Keep libraries in the build directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags
if(MSVC)
    # Use static runtime linking to avoid dependency on Visual C++ Redistributables
    # This makes the executable self-contained and runnable on systems without VC++ runtime
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    add_compile_options(/MP)  # Multi-processor compilation
    
    # Debug/Release specific flags
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
endif()

# Windows SDK is automatically found by Visual Studio generator
# No need for explicit find_package

# Third-party dependencies
add_subdirectory(third_party)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Add third-party includes after they're configured
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zydis)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/zydis/include)
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/include)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/json/include)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/core/syscall_extractor.cpp
    src/core/os_info.cpp
    src/core/module_manager.cpp
    src/symbols/pdb_downloader.cpp
    src/symbols/dia_symbol_parser.cpp
    src/symbols/dbghelp_symbol_parser.cpp
    src/disasm/disassembler.cpp
    src/disasm/x64_analyzer.cpp
    src/disasm/arm64_analyzer.cpp
    src/disasm/x86_analyzer.cpp
    src/output/json_formatter.cpp
    src/output/c_header_formatter.cpp
    src/utils/pe_parser.cpp
    src/utils/logger.cpp
    src/utils/string_utils.cpp
    src/analysis/automated_param_resolver.cpp
    src/analysis/syscall_patterns.cpp
    src/analysis/phnt_database.cpp
)

set(HEADERS
    include/syscall_extractor.h
    include/types.h
    include/os_info.h
    include/module_manager.h
    include/symbols/pdb_downloader.h
    include/symbols/symbol_parser.h
    include/symbols/syscall_info.h
    include/symbols/dia_symbol_parser.h
    include/symbols/dbghelp_symbol_parser.h
    include/disasm/disassembler.h
    include/disasm/instruction_analyzer.h
    include/output/formatter.h
    include/output/json_formatter.h
    include/output/c_header_formatter.h
    include/utils/pe_parser.h
    include/utils/logger.h
    include/utils/string_utils.h
    include/utils/error.h
    include/analysis/automated_param_resolver.h
    include/analysis/phnt_database.h
)

# Main executable
add_executable(ntsleuth ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(ntsleuth PRIVATE
    dbghelp
    version
    wininet
    urlmon
)

# Link third-party libraries if available
if(TARGET Zydis)
    target_link_libraries(ntsleuth PRIVATE Zydis)
endif()

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(ntsleuth PRIVATE nlohmann_json::nlohmann_json)
endif()

# DIA SDK linkage (optional, requires Visual Studio)
if(MSVC)
    # Try to find DIA SDK
    set(DIA_SDK_PATH "$ENV{VSINSTALLDIR}/DIA SDK")
    if(EXISTS "${DIA_SDK_PATH}")
        message(STATUS "Found DIA SDK at ${DIA_SDK_PATH}")
        target_include_directories(ntsleuth PRIVATE "${DIA_SDK_PATH}/include")
        if(TARGET_ARCH STREQUAL "x64")
            target_link_directories(ntsleuth PRIVATE "${DIA_SDK_PATH}/lib/amd64")
        elseif(TARGET_ARCH STREQUAL "ARM64")
            target_link_directories(ntsleuth PRIVATE "${DIA_SDK_PATH}/lib/arm64")
        else()
            target_link_directories(ntsleuth PRIVATE "${DIA_SDK_PATH}/lib")
        endif()
        target_link_libraries(ntsleuth PRIVATE diaguids)
        target_compile_definitions(ntsleuth PRIVATE HAS_DIA_SDK)
    else()
        message(WARNING "DIA SDK not found, falling back to DbgHelp only")
    endif()
endif()

# Installation
install(TARGETS ntsleuth RUNTIME DESTINATION bin)
install(DIRECTORY cache DESTINATION .)
install(FILES README.md LICENSE DESTINATION .)