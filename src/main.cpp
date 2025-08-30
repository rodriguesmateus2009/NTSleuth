// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2024 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "syscall_extractor.h"
#include "output/json_formatter.h"
#include "output/c_header_formatter.h"
#include "utils/logger.h"
#include "analysis/automated_param_resolver.h"
#include "analysis/phnt_database.h"
#include "os_info.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <Windows.h>
#include <nlohmann/json.hpp>

using namespace WinSyscall;

void SetConsoleUTF8()
{
#ifdef _WIN32
    // Set console code page to UTF-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    // Enable virtual terminal processing for ANSI colors
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif
}

void PrintBanner()
{
    std::cout << "\033[36m" << R"(
    ███   ██ ████████ ███████ ██      ███████ ██   ██ ████████ ██  ██
    ████  ██    ██    ██      ██      ██      ██   ██    ██    ██  ██
    ██ ██ ██    ██    ███████ ██      █████   ██   ██    ██    ███████
    ██  ████    ██         ██ ██      ██      ██   ██    ██    ██  ██
    ██   ███    ██    ███████ ███████ ███████  ██████    ██    ██  ██
                                                                        )"
              << "\033[0m\n";

    std::cout << "\033[35m" << R"(
  +===================================================================+
  |  Windows Syscall Extraction & Automated Parameter Resolution Tool |
  |                 ARM64 | x64 | x86 Syscall Analysis                |
  |               v1.0.0 by Alexander Hagenah • @xaitax               |
  +===================================================================+)"
              << "\033[0m\n\n";
}

void PrintUsage(const char *program_name)
{
    PrintBanner();
    std::cout << "\033[36mUsage:\033[0m " << program_name << " [options]\n\n";
    std::cout << "\033[36m[Options]\033[0m\n";
    std::cout << "  \033[33m-h, --help\033[0m              Show this help message\n";
    std::cout << "  \033[33m-o, --output\033[0m <path>     Output directory (default: output)\n";
    std::cout << "  \033[33m-c, --cache\033[0m <path>      Symbol cache directory (default: cache\\symbols)\n";
    std::cout << "  \033[33m-f, --format\033[0m <type>     Output format: json, header, both (default: both)\n";
    std::cout << "  \033[33m--no-ntdll\033[0m              Skip ntdll.dll extraction\n";
    std::cout << "  \033[33m--no-win32u\033[0m             Skip win32u.dll extraction\n";
    std::cout << "  \033[33m--wow64\033[0m                 Extract WOW64 (32-bit) syscalls\n";
    std::cout << "  \033[33m--no-symbols\033[0m            Don't download symbols\n";
    std::cout << "  \033[33m--no-cache\033[0m              Don't use symbol cache\n";
    std::cout << "  \033[33m--include-non-syscalls\033[0m  Include functions without syscall/svc instruction\n";
    std::cout << "  \033[33m--auto-params\033[0m           Enable automated parameter resolution\n";
    std::cout << "  \033[33m--param-confidence\033[0m <n>  Minimum confidence for parameter resolution (0.0-1.0)\n";
    std::cout << "  \033[33m--lookup\033[0m <name>         Look up specific syscall from syscalls.json\n";
    std::cout << "  \033[33m--clear-cache\033[0m           Clear all caches and force re-download\n";
    std::cout << "  \033[33m-v, --verbose\033[0m           Enable verbose logging\n";
    std::cout << "  \033[33m--log-file\033[0m <path>       Log to file\n";
    std::cout << "\n";
}

void LookupSyscall(const std::string &syscall_name, const std::string &json_path)
{
    // Check if JSON file exists
    if (!std::filesystem::exists(json_path))
    {
        std::cerr << "\033[31m[!] Error:\033[0m syscalls.json not found at '" << json_path << "'\n";
        std::cerr << "    Run the tool without --lookup first to generate the syscall database.\n";
        return;
    }

    // Load JSON file
    std::ifstream file(json_path);
    if (!file.is_open())
    {
        std::cerr << "\033[31m[!] Error:\033[0m Failed to open " << json_path << "\n";
        return;
    }

    nlohmann::json data;
    try
    {
        file >> data;
    }
    catch (const std::exception &e)
    {
        std::cerr << "\033[31m[!] Error:\033[0m Failed to parse JSON: " << e.what() << "\n";
        return;
    }
    file.close();

    // Search for syscall
    bool found = false;
    for (const auto &syscall : data["syscalls"])
    {
        if (syscall["name"] == syscall_name)
        {
            found = true;

            // Print header
            std::cout << "\n\033[36m" << std::string(70, '=') << "\033[0m\n";
            std::cout << "\033[35m  SYSCALL INFORMATION: \033[33m" << syscall_name << "\033[0m\n";
            std::cout << "\033[36m" << std::string(70, '=') << "\033[0m\n\n";

            // Basic info
            std::cout << "\033[32m[Module]\033[0m        " << syscall["module"].get<std::string>() << "\n";
            std::cout << "\033[32m[Number]\033[0m        0x" << std::hex << std::uppercase
                      << syscall["syscall_number"].get<uint32_t>() << std::dec << " ("
                      << syscall["syscall_number"].get<uint32_t>() << ")\n";
            std::cout << "\033[32m[RVA]\033[0m           0x" << std::hex << std::uppercase
                      << syscall["rva"].get<uint64_t>() << std::dec << "\n";
            std::cout << "\033[32m[Return Type]\033[0m   " << syscall["return_type"].get<std::string>() << "\n";
            std::cout << "\033[32m[Convention]\033[0m    " << syscall["calling_convention"].get<std::string>() << "\n";
            std::cout << "\033[32m[Is Syscall]\033[0m    "
                      << (syscall["is_true_syscall"].get<bool>() ? "\033[32mYes\033[0m" : "\033[31mNo\033[0m") << "\n";

            // Parameters
            if (syscall.contains("parameters") && !syscall["parameters"].empty())
            {
                std::cout << "\n\033[35m[Parameters]\033[0m\n";
                std::cout << "\033[36m" << std::string(70, '-') << "\033[0m\n";

                int index = 0;
                for (const auto &param : syscall["parameters"])
                {
                    std::cout << "  \033[33m[" << index++ << "]\033[0m ";

                    // Type
                    std::cout << "\033[36m" << std::setw(20) << std::left
                              << param["type"].get<std::string>() << "\033[0m ";

                    // Name
                    std::cout << "\033[32m" << std::setw(20) << std::left
                              << param["name"].get<std::string>() << "\033[0m";

                    // Show SAL annotation if present
                    if (param.contains("sal_annotation") && !param["sal_annotation"].get<std::string>().empty())
                    {
                        std::cout << " \033[93m[" << param["sal_annotation"].get<std::string>() << "]\033[0m";
                    }
                    else
                    {
                        // Fall back to showing basic attributes if no SAL annotation
                        std::vector<std::string> attrs;
                        if (param.contains("is_pointer") && param["is_pointer"].get<bool>())
                        {
                            attrs.push_back("pointer");
                        }
                        if (param.contains("is_optional") && param["is_optional"].get<bool>())
                        {
                            attrs.push_back("optional");
                        }
                        if (param.contains("is_const") && param["is_const"].get<bool>())
                        {
                            attrs.push_back("const");
                        }

                        if (!attrs.empty())
                        {
                            std::cout << " \033[90m[";
                            for (size_t i = 0; i < attrs.size(); ++i)
                            {
                                if (i > 0)
                                    std::cout << ", ";
                                std::cout << attrs[i];
                            }
                            std::cout << "]\033[0m";
                        }
                    }

                    std::cout << "\n";
                }
            }
            else
            {
                std::cout << "\n\033[33m[Parameters]\033[0m    None or not resolved\n";
            }

            // Function signature
            std::cout << "\n\033[35m[Function Signature]\033[0m\n";
            std::cout << "\033[36m" << std::string(70, '-') << "\033[0m\n";
            std::cout << "  \033[36m" << syscall["return_type"].get<std::string>() << " \033[33m"
                      << syscall["calling_convention"].get<std::string>() << " \033[32m"
                      << syscall_name << "\033[0m(\n";

            if (syscall.contains("parameters") && !syscall["parameters"].empty())
            {
                size_t param_count = syscall["parameters"].size();
                size_t current = 0;
                for (const auto &param : syscall["parameters"])
                {
                    // Show SAL annotation in signature if present
                    if (param.contains("sal_annotation") && !param["sal_annotation"].get<std::string>().empty())
                    {
                        std::cout << "    \033[93m" << param["sal_annotation"].get<std::string>() << "\033[0m ";
                    }
                    else
                    {
                        std::cout << "    ";
                    }
                    std::cout << "\033[36m" << param["type"].get<std::string>()
                              << "\033[0m " << param["name"].get<std::string>();
                    if (++current < param_count)
                        std::cout << ",";
                    std::cout << "\n";
                }
            }
            else
            {
                std::cout << "    \033[90mVOID\033[0m\n";
            }
            std::cout << "  );\n";

            // Stub bytes (first 32 bytes)
            if (syscall.contains("stub_bytes") && !syscall["stub_bytes"].get<std::string>().empty())
            {
                std::cout << "\n\033[35m[Stub Bytes]\033[0m (first 32 bytes)\n";
                std::cout << "\033[36m" << std::string(70, '-') << "\033[0m\n";
                std::string stub = syscall["stub_bytes"].get<std::string>();

                // Format as hex dump
                for (size_t i = 0; i < stub.length() && i < 64; i += 2)
                {
                    if (i % 32 == 0 && i > 0)
                        std::cout << "\n";
                    if (i % 32 == 0)
                        std::cout << "  ";
                    std::cout << stub.substr(i, 2) << " ";
                }
                std::cout << "\n";
            }

            // Check for aliases
            if (syscall.contains("alias_of") && !syscall["alias_of"].get<std::string>().empty())
            {
                std::cout << "\n\033[33m[Note]\033[0m This is an alias of: \033[36m"
                          << syscall["alias_of"].get<std::string>() << "\033[0m\n";
            }

            // Add documentation link
            std::cout << "\n\033[35m[Documentation]\033[0m\n";
            std::cout << "\033[36m" << std::string(70, '-') << "\033[0m\n";

            // Convert function name to lowercase for URL (NtCreateProcess -> ntcreateprocess)
            std::string url_name = syscall_name;
            std::transform(url_name.begin(), url_name.end(), url_name.begin(),
                           [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });

            std::cout << "  \033[36mhttps://ntdoc.m417z.com/" << url_name << "\033[0m\n";
            std::cout << "  \033[90m(Detailed parameter documentation and usage examples)\033[0m\n";

            std::cout << "\n\033[36m" << std::string(70, '=') << "\033[0m\n\n";
            break;
        }
    }

    if (!found)
    {
        std::cerr << "\033[31m[!] Error:\033[0m Syscall '" << syscall_name << "' not found in database.\n";
        std::cerr << "    Make sure the name is exact (case-sensitive).\n";

        // Try to find similar names
        std::vector<std::string> suggestions;
        std::string lower_search = syscall_name;
        std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });

        for (const auto &syscall : data["syscalls"])
        {
            std::string name = syscall["name"].get<std::string>();
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                           [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });

            if (lower_name.find(lower_search) != std::string::npos ||
                lower_search.find(lower_name) != std::string::npos)
            {
                suggestions.push_back(name);
                if (suggestions.size() >= 5)
                    break; // Limit suggestions
            }
        }

        if (!suggestions.empty())
        {
            std::cout << "\n\033[33m[Suggestions]\033[0m Did you mean:\n";
            for (const auto &suggestion : suggestions)
            {
                std::cout << "  - " << suggestion << "\n";
            }
        }
    }
}

int main(int argc, char *argv[])
{
    try
    {
        // Set console to UTF-8 mode
        SetConsoleUTF8();

        // Configure logger - disable console output for INFO messages
        Logger &logger = Logger::Instance();
        logger.EnableConsoleOutput(false);     // Disable console output for logger
        logger.SetLogLevel(LogLevel::Warning); // Only log warnings and errors to console
        logger.EnableTimestamp(false);         // Disable timestamps

        // Parse command line arguments
        ExtractionConfig config;
        std::string output_format = "both";
        std::string log_file;
        bool auto_resolve_params = false;
        double param_confidence = 0.7;
        std::string lookup_syscall;
        bool lookup_mode = false;
        bool clear_cache = false;

        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];

            if (arg == "-h" || arg == "--help")
            {
                PrintUsage(argv[0]);
                return 0;
            }
            else if (arg == "-o" || arg == "--output")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                config.output_directory = argv[i];
            }
            else if (arg == "-c" || arg == "--cache")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                config.symbol_cache_path = argv[i];
            }
            else if (arg == "-f" || arg == "--format")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                output_format = argv[i];
                if (output_format != "json" && output_format != "header" && output_format != "both")
                {
                    std::cerr << "Error: Invalid format '" << output_format << "'. Use json, header, or both.\n";
                    return 1;
                }
            }
            else if (arg == "--no-ntdll")
            {
                config.extract_ntdll = false;
            }
            else if (arg == "--no-win32u")
            {
                config.extract_win32u = false;
            }
            else if (arg == "--wow64")
            {
                config.extract_wow64 = true;
            }
            else if (arg == "--no-symbols")
            {
                config.download_symbols = false;
            }
            else if (arg == "--no-cache")
            {
                config.use_symbol_cache = false;
            }
            else if (arg == "--include-non-syscalls")
            {
                config.extract_non_syscalls = true;
            }
            else if (arg == "--auto-params")
            {
                auto_resolve_params = true;
            }
            else if (arg == "--param-confidence")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                param_confidence = std::stod(argv[i]);
                if (param_confidence < 0.0 || param_confidence > 1.0)
                {
                    std::cerr << "Error: Confidence must be between 0.0 and 1.0\n";
                    return 1;
                }
            }
            else if (arg == "-v" || arg == "--verbose")
            {
                config.verbose_logging = true;
                logger.SetLogLevel(LogLevel::Debug);
            }
            else if (arg == "--log-file")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                log_file = argv[i];
            }
            else if (arg == "--lookup")
            {
                if (++i >= argc)
                {
                    std::cerr << "Error: Missing argument for " << arg << "\n";
                    return 1;
                }
                lookup_syscall = argv[i];
                lookup_mode = true;
            }
            else if (arg == "--clear-cache")
            {
                clear_cache = true;
            }
            else
            {
                std::cerr << "Error: Unknown option '" << arg << "'\n";
                PrintUsage(argv[0]);
                return 1;
            }
        }

        // Setup log file if specified
        if (!log_file.empty())
        {
            logger.SetLogFile(log_file);
            logger.EnableFileOutput(true);
        }

        // Handle cache clearing if requested
        if (clear_cache)
        {
            std::cout << "\033[31m[!] Clearing all caches...\033[0m\n";

            // Clear symbol cache
            std::string symbol_cache = config.symbol_cache_path;
            if (std::filesystem::exists(symbol_cache))
            {
                std::filesystem::remove_all(symbol_cache);
                std::cout << "  \033[33m->\033[0m Removed symbol cache: " << symbol_cache << "\n";
            }

            // Clear PHNT cache
            std::string phnt_cache = "cache/phnt";
            if (std::filesystem::exists(phnt_cache))
            {
                std::filesystem::remove_all(phnt_cache);
                std::cout << "  \033[33m->\033[0m Removed PHNT cache: " << phnt_cache << "\n";
            }

            // Clear output directory if exists
            if (std::filesystem::exists(config.output_directory))
            {
                std::filesystem::remove_all(config.output_directory);
                std::cout << "  \033[33m->\033[0m Removed output directory: " << config.output_directory << "\n";
            }

            std::cout << "\033[32m[+] All caches cleared successfully!\033[0m\n";

            // If only clearing cache, exit
            if (!lookup_mode && !auto_resolve_params && argc == 2)
            {
                return 0;
            }
        }

        // Handle lookup mode
        if (lookup_mode)
        {
            PrintBanner();
            std::string json_path = config.output_directory + "/syscalls.json";
            LookupSyscall(lookup_syscall, json_path);
            return 0;
        }

        PrintBanner();

        // Create output directory
        std::filesystem::create_directories(config.output_directory);

        // Create extractor
        SyscallExtractor extractor;
        extractor.SetConfig(config);

        // === INITIALIZATION PHASE ===
        std::cout << "\033[35m[*] INITIALIZATION\033[0m\n\n";

        std::cout << "\033[32m[+]\033[0m Initializing NtSleuth Engine...\n";
        std::cout << "\033[32m[+]\033[0m Output directory: \033[33m" << config.output_directory << "\033[0m\n";
        std::cout << "\033[32m[+]\033[0m Symbol cache: \033[33m" << config.symbol_cache_path << "\033[0m\n";

        if (auto_resolve_params)
        {
            std::cout << "\033[32m[+]\033[0m Parameter resolution: \033[31mENABLED\033[0m (Confidence: " << param_confidence << ")\n";
        }
        std::cout << "\n";

        // === PHNT DATABASE PHASE ===
        std::cout << "\033[35m[*] PARAMETER DATABASE\033[0m\n\n";

        std::cout << "\033[32m[+]\033[0m Loading PHNT database for parameter resolution...\n";
        using namespace windows_arm64_analyzer;

        auto phnt_db = std::make_shared<analysis::PHNTDatabase>();
        bool phnt_loaded = false;

        // Try to load cached database first
        std::string json_cache = "cache/phnt/phnt_database.json";
        if (std::filesystem::exists(json_cache) && !clear_cache)
        {
            if (phnt_db->ImportFromJSON(json_cache))
            {
                phnt_loaded = true;
                auto stats = phnt_db->GetStatistics();
                std::cout << "\033[32m[+]\033[0m Loaded cached PHNT database with \033[35m"
                          << stats.total_functions << "\033[0m function signatures\n";
            }
        }

        // If no cache, try to initialize from headers
        if (!phnt_loaded)
        {
            if (phnt_db->Initialize())
            {
                phnt_loaded = true;
                auto stats = phnt_db->GetStatistics();
                std::cout << "\033[32m[+]\033[0m PHNT database initialized with \033[35m"
                          << stats.total_functions << "\033[0m function signatures\n";
                // Cache for next time
                std::filesystem::create_directories("cache/phnt");
                phnt_db->ExportToJSON(json_cache);
            }
            else
            {
                std::cout << "\033[33m[!]\033[0m PHNT database unavailable - parameters may be incomplete\n";
            }
        }

        // === EXTRACTION PHASE ===
        std::cout << "\n\033[35m[*] SYSCALL EXTRACTION\033[0m\n\n";

        std::cout << "\033[32m[+]\033[0m Extracting syscalls from system modules...\n";

        auto start_time = std::chrono::high_resolution_clock::now();
        ExtractionResult result = extractor.Extract();
        auto end_time = std::chrono::high_resolution_clock::now();

        result.extraction_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        end_time - start_time)
                                        .count();

        // === PARAMETER RESOLUTION PHASE ===
        std::cout << "\n\033[35m[*] PARAMETER RESOLUTION\033[0m\n\n";

        // Basic parameter resolution from PHNT (always enabled)
        if (phnt_loaded && phnt_db->GetAllFunctions().size() > 0)
        {
            std::cout << "\033[32m[+]\033[0m Resolving parameters from PHNT database...\n";

            size_t resolved_from_phnt = 0;
            for (auto &syscall : result.syscalls)
            {
                auto phnt_func = phnt_db->LookupFunction(syscall.name);
                if (phnt_func.has_value())
                {
                    // Clear any broken parameters
                    syscall.parameters.clear();

                    // Add PHNT parameters
                    for (const auto &phnt_param : phnt_func->parameters)
                    {
                        Parameter p;
                        p.type = phnt_param.type;
                        p.name = phnt_param.name;
                        p.is_pointer = (phnt_param.type.find('*') != std::string::npos ||
                                        phnt_param.type[0] == 'P' || phnt_param.type.substr(0, 2) == "LP");
                        p.is_optional = phnt_param.is_optional;
                        p.is_const = (phnt_param.type.find("CONST") != std::string::npos);
                        p.is_input = phnt_param.is_input;
                        p.is_output = phnt_param.is_output;
                        p.sal_annotation = phnt_param.direction;

                        syscall.parameters.push_back(p);
                    }
                    resolved_from_phnt++;
                }
            }

            if (resolved_from_phnt > 0)
            {
                std::cout << "\033[32m[+]\033[0m Resolved parameters for \033[35m"
                          << resolved_from_phnt << "\033[0m syscalls from PHNT\n";
            }
        }

        // Advanced automated parameter resolution if requested
        if (auto_resolve_params)
        {
            std::cout << "\n\033[33m[*] ADVANCED RESOLUTION\033[0m\n\n";

            std::cout << "\033[32m[+]\033[0m Initializing advanced parameter resolver...\n";
            std::cout << "\033[32m[+]\033[0m Analyzing " << result.syscalls.size() << " syscalls with heuristics...\n";

            auto param_start = std::chrono::high_resolution_clock::now();

            // Use enhanced resolver with PHNT database
            std::unique_ptr<analysis::AutomatedParamResolver> resolver;
            if (phnt_db && phnt_db->GetAllFunctions().size() > 0)
            {
                auto enhanced = std::make_unique<analysis::PHNTEnhancedResolver>();
                enhanced->SetDatabase(phnt_db);
                resolver = std::move(enhanced);
            }
            else
            {
                resolver = std::make_unique<analysis::AutomatedParamResolver>();
            }
            resolver->SetConfidenceThreshold(param_confidence);

            // Convert result.syscalls to SyscallInfo format
            std::vector<symbols::SyscallInfo> syscall_infos;
            for (const auto &sc : result.syscalls)
            {
                symbols::SyscallInfo info;
                info.name = sc.name;
                info.syscall_number = sc.syscall_number;
                info.module = sc.module_name;
                info.address = 0; // Not available in main Syscall struct
                info.rva = static_cast<size_t>(sc.rva);  // Explicit cast from uint64_t to size_t
                info.stub_bytes = sc.stub_bytes;
                info.return_type = sc.return_type;

                // Convert calling convention enum to string
                switch (sc.calling_convention)
                {
                case CallingConvention::Stdcall:
                    info.calling_convention = "stdcall";
                    break;
                case CallingConvention::Fastcall:
                    info.calling_convention = "fastcall";
                    break;
                case CallingConvention::Cdecl:
                    info.calling_convention = "cdecl";
                    break;
                case CallingConvention::Thiscall:
                    info.calling_convention = "thiscall";
                    break;
                default:
                    info.calling_convention = "unknown";
                    break;
                }

                info.is_true_syscall = sc.is_true_syscall;
                info.alias_of = sc.alias_of;
                syscall_infos.push_back(info);
            }

            // Resolve parameters
            auto resolved = resolver->ResolveAllSyscalls(syscall_infos);

            // Update syscalls with resolved parameters
            size_t resolved_count = 0;
            size_t partial_count = 0;

            for (auto &syscall : result.syscalls)
            {
                auto it = resolved.find(syscall.name);
                if (it != resolved.end() && it->second.confidence > 0.0)
                {
                    // Clear existing empty parameters
                    syscall.parameters.clear();

                    // Add resolved parameters
                    for (const auto &param : it->second.parameters)
                    {
                        Parameter p;
                        p.type = param.type_name;
                        p.name = param.name;
                        p.is_pointer = (param.type == analysis::ParamType::Pointer);
                        p.is_optional = param.is_optional;
                        p.is_input = !param.is_output; // Default to input unless marked as output
                        p.is_output = param.is_output;

                        // Build SAL annotation string
                        if (param.is_output && !param.is_input)
                        {
                            p.sal_annotation = param.is_optional ? "_Out_opt_" : "_Out_";
                        }
                        else if (param.is_output && param.is_input)
                        {
                            p.sal_annotation = param.is_optional ? "_Inout_opt_" : "_Inout_";
                        }
                        else
                        {
                            p.sal_annotation = param.is_optional ? "_In_opt_" : "_In_";
                        }

                        syscall.parameters.push_back(p);
                    }

                    if (it->second.confidence >= param_confidence)
                    {
                        resolved_count++;
                    }
                    else
                    {
                        partial_count++;
                    }
                }
            }

            auto param_end = std::chrono::high_resolution_clock::now();
            auto param_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  param_end - param_start)
                                  .count();

            // Print resolution statistics
            auto stats = resolver->GetStatistics();
            std::cout << "\n\033[33m[*] Advanced Resolution Statistics:\033[0m\n";
            std::cout << "    \033[36m->\033[0m Total processed: \033[32m" << stats.total_syscalls << "\033[0m\n";
            std::cout << "    \033[36m->\033[0m Fully resolved: \033[32m" << stats.resolved_fully << "\033[0m\n";
            std::cout << "    \033[36m->\033[0m Partially resolved: \033[33m" << stats.resolved_partially << "\033[0m\n";
            std::cout << "    \033[36m->\033[0m Failed: \033[31m" << stats.failed << "\033[0m\n";
            std::cout << "    \033[36m->\033[0m Average confidence: \033[35m" << std::fixed << std::setprecision(2)
                      << stats.average_confidence << "\033[0m\n";
            std::cout << "    \033[36m->\033[0m Resolution time: \033[35m" << param_time << " ms\033[0m\n";

            // result.warnings.push_back("Advanced parameter resolution is experimental and may not be 100% accurate");
        }

        // === EXTRACTION RESULTS ===
        std::cout << "\n\033[35m[*] EXTRACTION RESULTS\033[0m\n\n";

        // System Information
        std::cout << "\033[33m> System Information\033[0m\n";
        std::cout << "  \033[32m*\033[0m Target OS: " << result.os_info.version_string;

        switch (result.os_info.architecture)
        {
        case Architecture::x64:
            std::cout << " (x64)";
            break;
        case Architecture::ARM64:
            std::cout << " (ARM64)";
            break;
        case Architecture::x86:
            std::cout << " (x86)";
            break;
        default:
            std::cout << " (Unknown)";
            break;
        }

        if (result.os_info.is_wow64)
        {
            std::cout << " [WOW64]";
        }
        std::cout << "\n";

        std::cout << "  \033[32m*\033[0m Build: " << result.os_info.build_number;
        if (result.os_info.revision > 0)
        {
            std::cout << "." << result.os_info.revision;
        }
        std::cout << "\n\n";

        // Syscall Statistics
        std::cout << "\033[33m> Syscall Statistics\033[0m\n";
        std::cout << "  \033[32m*\033[0m Total syscalls found: \033[35m" << result.syscalls.size() << "\033[0m\n";

        // Count by module
        std::map<std::string, int> module_counts;
        std::map<std::string, int> true_syscall_counts;

        for (const auto &syscall : result.syscalls)
        {
            module_counts[syscall.module_name]++;
            if (syscall.is_true_syscall)
            {
                true_syscall_counts[syscall.module_name]++;
            }
        }

        for (const auto &[module, count] : module_counts)
        {
            std::cout << "    \033[36m->\033[0m " << module << ": \033[32m" << count << "\033[0m total";
            if (true_syscall_counts[module] != count)
            {
                std::cout << " (\033[33m" << true_syscall_counts[module] << "\033[0m true syscalls)";
            }
            std::cout << "\n";
        }
        std::cout << "\n";

        // Performance Metrics
        std::cout << "\033[33m> Performance Metrics\033[0m\n";
        std::cout << "  \033[32m*\033[0m Extraction time: \033[35m" << result.extraction_time_ms << " ms\033[0m\n";

        // Print errors and warnings
        if (!result.errors.empty())
        {
            std::cout << "\nErrors:\n";
            for (const auto &error : result.errors)
            {
                std::cout << "  - " << error << "\n";
            }
        }

        if (!result.warnings.empty())
        {
            std::cout << "\nWarnings:\n";
            for (const auto &warning : result.warnings)
            {
                std::cout << "  - " << warning << "\n";
            }
        }

        // === SAVING RESULTS ===
        std::cout << "\n\033[35m[*] SAVING RESULTS\033[0m\n\n";

        bool save_json = (output_format == "json" || output_format == "both");
        bool save_header = (output_format == "header" || output_format == "both");

        if (save_json)
        {
            std::string json_path = config.output_directory + "/syscalls.json";
            if (extractor.SaveToJson(result, json_path))
            {
                std::cout << "\033[32m[+]\033[0m JSON output saved to: \033[33m" << json_path << "\033[0m\n";
            }
            else
            {
                std::cerr << "\033[31m[-]\033[0m Failed to save JSON output\n";
            }
        }

        if (save_header)
        {
            std::string header_path = config.output_directory + "/syscalls.h";
            if (extractor.SaveToCHeader(result, header_path))
            {
                std::cout << "\033[32m[+]\033[0m C header saved to: \033[33m" << header_path << "\033[0m\n";
            }
            else
            {
                std::cerr << "\033[31m[-]\033[0m Failed to save C header\n";
            }
        }

        // === MISSION ACCOMPLISHED ===

        std::cout << "\n\033[35mNTSleuth has successfully extracted all syscalls!\033[0m\n";
        std::cout << "\033[35mHappy hunting!\033[0m\n\n";

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
    catch (...)
    {
        std::cerr << "Fatal error: Unknown exception\n";
        return 1;
    }
}
