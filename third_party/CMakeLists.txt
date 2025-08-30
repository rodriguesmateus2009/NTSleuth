# Third-party dependencies

include(FetchContent)

# Option to disable dependency fetching
option(FETCH_DEPENDENCIES "Automatically fetch dependencies" ON)

if(FETCH_DEPENDENCIES)
    # Zydis disassembler
    message(STATUS "Configuring Zydis disassembler...")
    FetchContent_Declare(
        Zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis.git
        GIT_TAG        v4.1.1
        GIT_SHALLOW    TRUE
    )
    
    # Configure Zydis options
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    
    FetchContent_MakeAvailable(Zydis)
    
    # JSON library - single header
    message(STATUS "Downloading nlohmann/json...")
    file(DOWNLOAD
        https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/json/include/nlohmann/json.hpp
        SHOW_PROGRESS
        STATUS download_status
    )
    
    list(GET download_status 0 status_code)
    if(NOT status_code EQUAL 0)
        message(WARNING "Failed to download json.hpp, will use simplified JSON output")
    endif()
endif()

# Create interface library for json (whether downloaded or not)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/json/include/nlohmann/json.hpp)
    add_library(nlohmann_json INTERFACE)
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
    target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/json/include)
    message(STATUS "JSON library configured")
else()
    # Create dummy target if json.hpp doesn't exist
    add_library(nlohmann_json INTERFACE)
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
    message(WARNING "JSON library not found, JSON output will be disabled")
endif()

# For local/manual Zydis installation
if(NOT TARGET Zydis AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/zydis)
    add_subdirectory(zydis)
endif()