// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "analysis/phnt_database.h"
#include "utils/logger.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <Windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace windows_arm64_analyzer
{
    namespace analysis
    {

        // List of important PHNT header files to download - comprehensive list
        const std::vector<std::string> PHNTDatabase::PHNT_HEADERS = {
            // Core NT APIs
            "ntexapi.h",      // Executive APIs (core system calls)
            "ntpsapi.h",      // Process APIs
            "ntioapi.h",      // I/O APIs
            "ntmmapi.h",      // Memory management APIs
            "ntobapi.h",      // Object manager APIs
            "ntregapi.h",     // Registry APIs
            "ntseapi.h",      // Security APIs
            "nttmapi.h",      // Transaction APIs
            "ntlpcapi.h",     // LPC/ALPC APIs
            "ntkeapi.h",      // Kernel APIs
            "ntrtl.h",        // Runtime library
            "ntzwapi.h",      // Zw* variants
            "ntldrapi.h",     // Loader APIs
            "ntpfapi.h",      // Prefetcher APIs
            "ntpnpapi.h",     // PnP APIs
            "ntpoapi.h",      // Power management APIs
            "ntdbg.h",        // Debug APIs
            "ntwow64.h",      // WOW64 APIs
            "ntconfig.h",     // Configuration Manager APIs
            "ntsam.h",        // SAM APIs
            "ntlsa.h",        // LSA APIs
            "ntmisc.h",       // Miscellaneous APIs
            "ntsmss.h",       // Session Manager APIs
            "ntcsrapi.h",     // CSR APIs
            "nttp.h",         // Thread Pool APIs
            "ntwmi.h",        // WMI APIs
            "ntpebteb.h",     // PEB/TEB structures
            "ntimage.h",      // Image/PE structures
            "ntgdi.h",        // GDI APIs
            "ntuser.h",       // User32 APIs
            "ntifs.h",        // Installable File System APIs
            "phnt.h",         // Main header
            "phnt_windows.h", // Windows definitions
            "phnt_ntdef.h"    // NT definitions
        };

        PHNTDatabase::PHNTDatabase()
            : initialized_(false),
              cache_directory_("cache/phnt")
        {
        }

        PHNTDatabase::~PHNTDatabase() = default;

        bool PHNTDatabase::Initialize(bool force_download)
        {
            if (initialized_ && !force_download)
            {
                return true;
            }

            // Create cache directory if it doesn't exist
            std::filesystem::create_directories(cache_directory_);

            // Check if we have cached headers
            bool has_cache = false;
            for (const auto &header : PHNT_HEADERS)
            {
                std::string file_path = cache_directory_ + "/" + header;
                if (std::filesystem::exists(file_path))
                {
                    has_cache = true;
                    break;
                }
            }

            // Download headers if needed
            if (!has_cache || force_download)
            {
                LOG_INFO("Downloading PHNT headers from System Informer repository...");
                if (!DownloadHeaders(cache_directory_))
                {
                    LOG_ERROR("Failed to download PHNT headers");
                    // Continue anyway, we might have some cached files
                }
            }

            // Parse all headers
            LOG_INFO("Parsing PHNT headers...");
            if (!ParseAllHeaders(cache_directory_))
            {
                LOG_ERROR("Failed to parse PHNT headers");
                return false;
            }

            // Try to load additional cached database
            std::string json_cache = cache_directory_ + "/phnt_database.json";
            if (std::filesystem::exists(json_cache) && !force_download)
            {
                LOG_INFO("Loading cached PHNT database...");
                ImportFromJSON(json_cache);
            }

            initialized_ = true;

            auto stats = GetStatistics();
            LOG_INFO("PHNT database initialized with " + std::to_string(stats.total_functions) +
                     " functions and " + std::to_string(stats.total_parameters) + " parameters");

            return true;
        }

        bool PHNTDatabase::DownloadHeaders(const std::string &cache_dir)
        {
            std::filesystem::create_directories(cache_dir);

            int success_count = 0;
            for (const auto &header : PHNT_HEADERS)
            {
                std::string url = std::string(PHNT_BASE_URL) + header;
                std::string output_path = cache_dir + "/" + header;

                LOG_DEBUG("Downloading " + header + "...");
                if (DownloadFile(url, output_path))
                {
                    success_count++;
                }
                else
                {
                    LOG_WARNING("Failed to download " + header);
                }
            }

            LOG_INFO("Downloaded " + std::to_string(success_count) + "/" +
                     std::to_string(PHNT_HEADERS.size()) + " headers");

            return success_count > 0;
        }

        bool PHNTDatabase::DownloadFile(const std::string &url, const std::string &output_path)
        {
            // Parse URL
            std::string host, path;
            size_t protocol_end = url.find("://");
            if (protocol_end != std::string::npos)
            {
                size_t host_start = protocol_end + 3;
                size_t path_start = url.find('/', host_start);
                if (path_start != std::string::npos)
                {
                    host = url.substr(host_start, path_start - host_start);
                    path = url.substr(path_start);
                }
                else
                {
                    host = url.substr(host_start);
                    path = "/";
                }
            }
            else
            {
                LOG_ERROR("Invalid URL: " + url);
                return false;
            }

            // Use WinHTTP to download
            HINTERNET hSession = WinHttpOpen(L"NTSleuth/1.0",
                                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                             WINHTTP_NO_PROXY_NAME,
                                             WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession)
            {
                LOG_ERROR("Failed to open WinHTTP session");
                return false;
            }

            std::wstring whost(host.begin(), host.end());
            HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(),
                                                INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect)
            {
                WinHttpCloseHandle(hSession);
                LOG_ERROR("Failed to connect to " + host);
                return false;
            }

            std::wstring wpath(path.begin(), path.end());
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                                    NULL, WINHTTP_NO_REFERER,
                                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                    WINHTTP_FLAG_SECURE);
            if (!hRequest)
            {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                LOG_ERROR("Failed to open request for " + path);
                return false;
            }

            // Send request
            if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                LOG_ERROR("Failed to send request");
                return false;
            }

            // Receive response
            if (!WinHttpReceiveResponse(hRequest, NULL))
            {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                LOG_ERROR("Failed to receive response");
                return false;
            }

            // Read data
            std::vector<char> buffer;
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;

            do
            {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                {
                    LOG_ERROR("Error in WinHttpQueryDataAvailable");
                    break;
                }

                if (dwSize == 0)
                    break;

                std::vector<char> temp_buffer(dwSize + 1);
                if (!WinHttpReadData(hRequest, temp_buffer.data(), dwSize, &dwDownloaded))
                {
                    LOG_ERROR("Error in WinHttpReadData");
                    break;
                }

                buffer.insert(buffer.end(), temp_buffer.begin(), temp_buffer.begin() + dwDownloaded);
            } while (dwSize > 0);

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            // Write to file
            std::ofstream file(output_path, std::ios::binary);
            if (!file)
            {
                LOG_ERROR("Failed to open output file: " + output_path);
                return false;
            }

            file.write(buffer.data(), buffer.size());
            file.close();

            LOG_DEBUG("Downloaded " + std::to_string(buffer.size()) + " bytes to " + output_path);
            return true;
        }

        bool PHNTDatabase::ParseAllHeaders(const std::string &directory)
        {
            int parsed_count = 0;

            for (const auto &header : PHNT_HEADERS)
            {
                std::string file_path = directory + "/" + header;
                if (std::filesystem::exists(file_path))
                {
                    if (ParseHeaderFile(file_path))
                    {
                        parsed_count++;
                    }
                }
            }

            LOG_INFO("Parsed " + std::to_string(parsed_count) + " header files");
            return parsed_count > 0;
        }

        bool PHNTDatabase::ParseHeaderFile(const std::string &file_path)
        {
            std::ifstream file(file_path);
            if (!file)
            {
                LOG_ERROR("Failed to open file: " + file_path);
                return false;
            }

            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            file.close();

            // Extract filename for source tracking
            std::filesystem::path path(file_path);
            std::string filename = path.filename().string();

            // Parse different API categories
            if (filename == "ntpsapi.h")
            {
                return ParseNtProcessApi(content);
            }
            else if (filename == "ntioapi.h" || filename == "ntfileapi.h")
            {
                return ParseNtFileApi(content);
            }
            else if (filename == "ntmmapi.h")
            {
                return ParseNtMemoryApi(content);
            }
            else if (filename == "ntregapi.h")
            {
                return ParseNtRegistryApi(content);
            }
            else if (filename == "ntseapi.h")
            {
                return ParseNtSecurityApi(content);
            }
            else
            {
                // Generic parsing for other headers
                return ParseNtSystemApi(content);
            }
        }

        bool PHNTDatabase::ParseNtProcessApi(const std::string &content)
        {
            // Parse NTSYSCALLAPI function declarations
            // We need to handle nested parentheses in SAL annotations like _In_reads_(Count)

            // Find function declarations by looking for NTSYSCALLAPI...NTAPI pattern
            size_t pos = 0;
            int count = 0;

            while ((pos = content.find("NTSYSCALLAPI", pos)) != std::string::npos)
            {
                // Find the function name (starts with Nt or Zw)
                size_t name_start = content.find("Nt", pos);
                if (name_start == std::string::npos || name_start > pos + 200)
                {
                    name_start = content.find("Zw", pos);
                    if (name_start == std::string::npos || name_start > pos + 200)
                    {
                        pos++;
                        continue;
                    }
                }

                // Extract function name
                size_t name_end = name_start;
                while (name_end < content.length() &&
                       (std::isalnum(content[name_end]) || content[name_end] == '_'))
                {
                    name_end++;
                }
                std::string func_name = content.substr(name_start, name_end - name_start);

                // Find the opening parenthesis for parameters
                size_t param_start = content.find('(', name_end);
                if (param_start == std::string::npos || param_start > name_end + 50)
                {
                    pos = name_end;
                    continue;
                }

                // Find the matching closing parenthesis (handle nested parentheses)
                size_t param_end = param_start + 1;
                int paren_depth = 1;
                while (param_end < content.length() && paren_depth > 0)
                {
                    if (content[param_end] == '(')
                    {
                        paren_depth++;
                    }
                    else if (content[param_end] == ')')
                    {
                        paren_depth--;
                    }
                    param_end++;
                }

                if (paren_depth != 0)
                {
                    pos = name_end;
                    continue;
                }

                // Extract parameters (between parentheses)
                std::string params = content.substr(param_start + 1, param_end - param_start - 2);

                // Create function entry
                PHNTFunction func;
                func.name = func_name;
                func.return_type = "NTSTATUS"; // Default for syscalls
                func.source_file = "ntpsapi.h";
                func.is_documented = false;

                // Parse parameters
                func.parameters = ParseParameters(params);

                // Store the function
                functions_[func_name] = func;
                count++;

                // Move to next position
                pos = param_end;
            }

            LOG_DEBUG("Parsed " + std::to_string(count) + " functions from ntpsapi.h");
            return count > 0;
        }

        std::vector<PHNTParameter> PHNTDatabase::ParseParameters(const std::string &params_str)
        {
            std::vector<PHNTParameter> parameters;

            // Clean up the parameters string
            std::string cleaned = params_str;
            cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '\n'), cleaned.end());
            cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '\r'), cleaned.end());

            // Split by comma (but be careful with nested templates/function pointers)
            std::vector<std::string> param_strings;
            std::string current_param;
            int paren_depth = 0;
            int angle_depth = 0;

            for (char c : cleaned)
            {
                if (c == ',' && paren_depth == 0 && angle_depth == 0)
                {
                    if (!current_param.empty())
                    {
                        param_strings.push_back(current_param);
                        current_param.clear();
                    }
                }
                else
                {
                    if (c == '(')
                        paren_depth++;
                    else if (c == ')')
                        paren_depth--;
                    else if (c == '<')
                        angle_depth++;
                    else if (c == '>')
                        angle_depth--;
                    current_param += c;
                }
            }

            if (!current_param.empty())
            {
                param_strings.push_back(current_param);
            }

            // Parse each parameter
            for (const auto &param_str : param_strings)
            {
                PHNTParameter param;

                // Trim whitespace
                std::string trimmed = param_str;
                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                trimmed.erase(trimmed.find_last_not_of(" \t") + 1);

                if (trimmed.empty() || trimmed == "VOID" || trimmed == "void")
                {
                    continue;
                }

                // Remove inline comments (// comment) but handle special cases
                size_t comment_pos = trimmed.find("//");
                std::string inline_comment;
                if (comment_pos != std::string::npos)
                {
                    // Extract everything after //
                    std::string after_comment = trimmed.substr(comment_pos + 2);

                    // Check if there's actual parameter declaration AFTER the comment
                    // This happens in cases like: // PROCESS_CREATE_FLAGS_* HANDLE SectionHandle
                    std::regex param_after_comment(R"(\s*(\w+\s+\w+))");
                    std::smatch match;
                    if (std::regex_search(after_comment, match, param_after_comment))
                    {
                        // The actual parameter is after the comment, extract just the comment part
                        size_t param_start = after_comment.find(match[0].str());
                        inline_comment = after_comment.substr(0, param_start);
                        // The actual parameter is what comes after
                        trimmed = after_comment.substr(param_start);
                    }
                    else
                    {
                        // Normal case: comment is at the end
                        inline_comment = after_comment;
                        trimmed = trimmed.substr(0, comment_pos);
                    }

                    // Clean up
                    trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                    trimmed.erase(trimmed.find_last_not_of(" \t") + 1);
                    inline_comment.erase(0, inline_comment.find_first_not_of(" \t"));
                    inline_comment.erase(inline_comment.find_last_not_of(" \t") + 1);
                }

                // Parse SAL annotations
                // We need to handle patterns like:
                // - Simple: _In_, _Out_, _In_opt_
                // - Complex: _In_reads_(Count), _Out_writes_bytes_(Size)
                std::string sal_annotation;

                // Look for SAL annotations at the start of the trimmed string
                // Match pattern: underscore followed by capital letter, then any combination of letters/underscores,
                // optionally followed by parentheses with content
                if (trimmed.length() > 0 && trimmed[0] == '_')
                {
                    // Find the end of the SAL annotation
                    size_t end_pos = 1;

                    // Skip through the annotation name (letters and underscores)
                    while (end_pos < trimmed.length() &&
                           (std::isalpha(trimmed[end_pos]) || trimmed[end_pos] == '_'))
                    {
                        end_pos++;
                    }

                    // Check if there's a parenthesized part
                    if (end_pos < trimmed.length() && trimmed[end_pos] == '(')
                    {
                        // Find the matching closing parenthesis
                        size_t paren_count = 1;
                        end_pos++;
                        while (end_pos < trimmed.length() && paren_count > 0)
                        {
                            if (trimmed[end_pos] == '(')
                                paren_count++;
                            else if (trimmed[end_pos] == ')')
                                paren_count--;
                            end_pos++;
                        }
                    }

                    // Extract the SAL annotation
                    sal_annotation = trimmed.substr(0, end_pos);

                    // Verify it's a known SAL annotation type
                    if (sal_annotation.find("_In") == 0 ||
                        sal_annotation.find("_Out") == 0 ||
                        sal_annotation.find("_Inout") == 0 ||
                        sal_annotation.find("_Reserved") == 0 ||
                        sal_annotation.find("_Field") == 0 ||
                        sal_annotation.find("_Pre") == 0 ||
                        sal_annotation.find("_Post") == 0)
                    {

                        // Remove the SAL annotation from trimmed
                        trimmed = trimmed.substr(end_pos);

                        // Store the annotation
                        param.annotations = sal_annotation;
                        param.direction = sal_annotation;

                        // Parse annotation properties
                        if (sal_annotation.find("_In") == 0)
                        {
                            param.is_input = true;
                            param.is_output = false;
                            param.is_optional = sal_annotation.find("opt") != std::string::npos;
                        }
                        else if (sal_annotation.find("_Out") == 0)
                        {
                            param.is_input = false;
                            param.is_output = true;
                            param.is_optional = sal_annotation.find("opt") != std::string::npos;
                        }
                        else if (sal_annotation.find("_Inout") == 0)
                        {
                            param.is_input = true;
                            param.is_output = true;
                            param.is_optional = sal_annotation.find("opt") != std::string::npos;
                        }
                        else if (sal_annotation.find("_Reserved") == 0)
                        {
                            param.is_input = false;
                            param.is_output = false;
                            param.is_optional = true;
                            param.description = "Reserved, must be zero or NULL";
                        }
                    }
                }

                // Clean up the remaining string after SAL removal
                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                trimmed.erase(trimmed.find_last_not_of(" \t") + 1);

                // Extract type and name
                // Handle array notation like "HANDLE Handles[]"
                std::regex array_param_regex(R"((.+?)\s+(\w+)\s*\[\s*\])");
                std::regex normal_param_regex(R"((.+?)\s+(\w+)$)");
                std::smatch param_match;

                if (std::regex_search(trimmed, param_match, array_param_regex))
                {
                    // Array parameter like "HANDLE Handles[]"
                    param.type = param_match[1].str() + "*"; // Convert array to pointer
                    param.name = param_match[2].str();

                    // Clean up type
                    param.type.erase(0, param.type.find_first_not_of(" \t"));
                    param.type.erase(param.type.find_last_not_of(" \t") + 1);
                }
                else if (std::regex_search(trimmed, param_match, normal_param_regex))
                {
                    // Normal parameter
                    param.type = param_match[1].str();
                    param.name = param_match[2].str();

                    // Clean up type
                    param.type.erase(0, param.type.find_first_not_of(" \t"));
                    param.type.erase(param.type.find_last_not_of(" \t") + 1);
                }
                else
                {
                    // Might be a type without name (e.g., in function pointers) or just "VOID"
                    param.type = trimmed;
                    param.name = "param" + std::to_string(parameters.size());
                }

                // If we found an inline comment, use it as description
                if (!inline_comment.empty())
                {
                    param.description = inline_comment;
                }

                parameters.push_back(param);
            }

            return parameters;
        }

        void PHNTDatabase::ParseSALAnnotations(PHNTParameter &param, const std::string &annotations)
        {
            // Parse common SAL annotations
            if (annotations.find("_In_") != std::string::npos)
            {
                param.is_input = true;
                param.is_output = false;
                param.is_optional = (annotations.find("_opt_") != std::string::npos);
            }
            else if (annotations.find("_Out_") != std::string::npos)
            {
                param.is_input = false;
                param.is_output = true;
                param.is_optional = (annotations.find("_opt_") != std::string::npos);
            }
            else if (annotations.find("_Inout_") != std::string::npos)
            {
                param.is_input = true;
                param.is_output = true;
                param.is_optional = (annotations.find("_opt_") != std::string::npos);
            }
            else if (annotations.find("_Reserved_") != std::string::npos)
            {
                param.is_input = false;
                param.is_output = false;
                param.is_optional = true;
                param.description = "Reserved, must be zero or NULL";
            }

            // Set direction string
            if (param.is_input && param.is_output)
            {
                param.direction = param.is_optional ? "_Inout_opt_" : "_Inout_";
            }
            else if (param.is_input)
            {
                param.direction = param.is_optional ? "_In_opt_" : "_In_";
            }
            else if (param.is_output)
            {
                param.direction = param.is_optional ? "_Out_opt_" : "_Out_";
            }
            else
            {
                param.direction = "_Reserved_";
            }
        }

        std::map<std::string, std::string> PHNTDatabase::ParseDoxygenComment(const std::string &comment)
        {
            std::map<std::string, std::string> result;

            // Extract main description (text before @param tags)
            std::regex desc_regex(R"(/\*\*\s*\n?\s*\*\s*([^@]+))");
            std::smatch desc_match;
            if (std::regex_search(comment, desc_match, desc_regex))
            {
                std::string desc = desc_match[1].str();
                // Remove leading asterisks and whitespace
                desc = std::regex_replace(desc, std::regex(R"(\n\s*\*\s*)"), " ");
                desc.erase(0, desc.find_first_not_of(" \t\n"));
                desc.erase(desc.find_last_not_of(" \t\n") + 1);
                result["description"] = desc;
            }

            // Extract @param descriptions
            std::regex param_regex(R"(@param\s+(\w+)\s+([^@]+))");
            std::sregex_iterator it(comment.begin(), comment.end(), param_regex);
            std::sregex_iterator end;

            while (it != end)
            {
                std::smatch match = *it;
                std::string param_name = match[1].str();
                std::string param_desc = match[2].str();

                // Clean up description
                param_desc = std::regex_replace(param_desc, std::regex(R"(\n\s*\*\s*)"), " ");
                param_desc.erase(0, param_desc.find_first_not_of(" \t\n"));
                param_desc.erase(param_desc.find_last_not_of(" \t\n"));

                result["@param " + param_name] = param_desc;
                ++it;
            }

            // Extract @return description
            std::regex return_regex(R"(@return\s+([^@]+))");
            std::smatch return_match;
            if (std::regex_search(comment, return_match, return_regex))
            {
                std::string return_desc = return_match[1].str();
                return_desc = std::regex_replace(return_desc, std::regex(R"(\n\s*\*\s*)"), " ");
                return_desc.erase(0, return_desc.find_first_not_of(" \t\n"));
                return_desc.erase(return_desc.find_last_not_of(" \t\n"));
                result["@return"] = return_desc;
            }

            return result;
        }

        std::optional<PHNTFunction> PHNTDatabase::LookupFunction(const std::string &function_name) const
        {
            auto it = functions_.find(function_name);
            if (it != functions_.end())
            {
                return it->second;
            }

            // Try with Zw prefix if Nt fails
            if (function_name.substr(0, 2) == "Nt")
            {
                std::string zw_name = "Zw" + function_name.substr(2);
                it = functions_.find(zw_name);
                if (it != functions_.end())
                {
                    return it->second;
                }
            }

            return std::nullopt;
        }

        SyscallSignature PHNTDatabase::ConvertToSignature(const PHNTFunction &func) const
        {
            SyscallSignature sig;
            sig.function_name = func.name;
            sig.return_type = func.return_type;
            sig.parameter_count = func.parameters.size();
            sig.is_verified = true; // From official headers
            sig.confidence = 1.0;   // Maximum confidence
            sig.detection_method = "PHNT Database";

            // Convert parameters
            for (size_t i = 0; i < func.parameters.size(); i++)
            {
                const auto &phnt_param = func.parameters[i];

                DetectedParameter param;
                param.index = i;
                param.type = ConvertToParamType(phnt_param.type);
                param.type_name = phnt_param.type;
                param.name = phnt_param.name;
                param.is_optional = phnt_param.is_optional;
                param.is_output = phnt_param.is_output;
                param.description = phnt_param.description;

                // Set size hints for buffer types
                if (phnt_param.type.find("PVOID") != std::string::npos ||
                    phnt_param.type.find("LPVOID") != std::string::npos)
                {
                    param.size_hint = 0; // Unknown size
                }

                sig.parameters.push_back(param);
            }

            return sig;
        }

        ParamType PHNTDatabase::ConvertToParamType(const std::string &type_str) const
        {
            std::string normalized = NormalizeType(type_str);

            if (normalized.find("HANDLE") != std::string::npos)
            {
                return ParamType::Handle;
            }
            else if (normalized.find("UNICODE_STRING") != std::string::npos)
            {
                return ParamType::UnicodeString;
            }
            else if (normalized.find("OBJECT_ATTRIBUTES") != std::string::npos)
            {
                return ParamType::ObjectAttributes;
            }
            else if (normalized.find("IO_STATUS_BLOCK") != std::string::npos)
            {
                return ParamType::IoStatusBlock;
            }
            else if (normalized.find("ACCESS_MASK") != std::string::npos)
            {
                return ParamType::AccessMask;
            }
            else if (normalized.find("LARGE_INTEGER") != std::string::npos)
            {
                return ParamType::LargeInteger;
            }
            else if (normalized.find("BOOLEAN") != std::string::npos)
            {
                return ParamType::Boolean;
            }
            else if (normalized.find("ULONG") != std::string::npos)
            {
                return ParamType::Ulong;
            }
            else if (normalized.find("SIZE_T") != std::string::npos)
            {
                return ParamType::Size;
            }
            else if (normalized.find("NTSTATUS") != std::string::npos)
            {
                return ParamType::Status;
            }
            else if (normalized[0] == 'P' || normalized.find("*") != std::string::npos)
            {
                return ParamType::Pointer;
            }
            else
            {
                return ParamType::Integer;
            }
        }

        std::string PHNTDatabase::NormalizeType(const std::string &type) const
        {
            std::string normalized = type;

            // Convert to uppercase for comparison
            std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                           [](unsigned char c)
                           { return static_cast<char>(std::toupper(c)); });

            // Remove const, volatile qualifiers
            normalized = std::regex_replace(normalized, std::regex(R"(\bCONST\b)"), "");
            normalized = std::regex_replace(normalized, std::regex(R"(\bVOLATILE\b)"), "");

            // Remove extra spaces
            normalized = std::regex_replace(normalized, std::regex(R"(\s+)"), " ");

            // Trim
            normalized.erase(0, normalized.find_first_not_of(" \t"));
            normalized.erase(normalized.find_last_not_of(" \t") + 1);

            return normalized;
        }

        PHNTDatabase::Statistics PHNTDatabase::GetStatistics() const
        {
            Statistics stats = {};
            stats.total_functions = functions_.size();

            for (const auto &[name, func] : functions_)
            {
                if (func.is_documented)
                {
                    stats.documented_functions++;
                }
                stats.total_parameters += func.parameters.size();

                for (const auto &param : func.parameters)
                {
                    stats.type_frequency[param.type]++;
                }
            }

            return stats;
        }

        bool PHNTDatabase::ExportToJSON(const std::string &output_path) const
        {
            nlohmann::json j;

            for (const auto &[name, func] : functions_)
            {
                nlohmann::json func_json;
                func_json["name"] = func.name;
                func_json["return_type"] = func.return_type;
                func_json["description"] = func.description;
                func_json["source_file"] = func.source_file;
                func_json["is_documented"] = func.is_documented;

                nlohmann::json params_json = nlohmann::json::array();
                for (const auto &param : func.parameters)
                {
                    nlohmann::json param_json;
                    param_json["name"] = param.name;
                    param_json["type"] = param.type;
                    param_json["direction"] = param.direction;
                    param_json["description"] = param.description;
                    param_json["is_optional"] = param.is_optional;
                    param_json["is_output"] = param.is_output;
                    param_json["is_input"] = param.is_input;
                    params_json.push_back(param_json);
                }
                func_json["parameters"] = params_json;

                j[name] = func_json;
            }

            std::ofstream file(output_path);
            if (!file)
            {
                LOG_ERROR("Failed to open output file: " + output_path);
                return false;
            }

            file << j.dump(2);
            file.close();

            LOG_INFO("Exported " + std::to_string(functions_.size()) + " functions to " + output_path);
            return true;
        }

        bool PHNTDatabase::ImportFromJSON(const std::string &input_path)
        {
            std::ifstream file(input_path);
            if (!file)
            {
                LOG_ERROR("Failed to open input file: " + input_path);
                return false;
            }

            nlohmann::json j;
            try
            {
                file >> j;
            }
            catch (const std::exception &e)
            {
                LOG_ERROR("Failed to parse JSON: " + std::string(e.what()));
                return false;
            }
            file.close();

            for (auto &[name, func_json] : j.items())
            {
                PHNTFunction func;
                func.name = func_json["name"];
                func.return_type = func_json["return_type"];
                func.description = func_json.value("description", "");
                func.source_file = func_json.value("source_file", "");
                func.is_documented = func_json.value("is_documented", false);

                if (func_json.contains("parameters"))
                {
                    for (auto &param_json : func_json["parameters"])
                    {
                        PHNTParameter param;
                        param.name = param_json["name"];
                        param.type = param_json["type"];
                        param.direction = param_json.value("direction", "");
                        param.description = param_json.value("description", "");
                        param.is_optional = param_json.value("is_optional", false);
                        param.is_output = param_json.value("is_output", false);
                        param.is_input = param_json.value("is_input", true);
                        func.parameters.push_back(param);
                    }
                }

                functions_[name] = func;
            }

            LOG_INFO("Imported " + std::to_string(functions_.size()) + " functions from " + input_path);
            return true;
        }

        // Stub implementations for other API categories
        bool PHNTDatabase::ParseNtFileApi(const std::string &content)
        {
            return ParseNtProcessApi(content); // Use same parsing logic
        }

        bool PHNTDatabase::ParseNtMemoryApi(const std::string &content)
        {
            return ParseNtProcessApi(content);
        }

        bool PHNTDatabase::ParseNtThreadApi(const std::string &content)
        {
            return ParseNtProcessApi(content);
        }

        bool PHNTDatabase::ParseNtRegistryApi(const std::string &content)
        {
            return ParseNtProcessApi(content);
        }

        bool PHNTDatabase::ParseNtSecurityApi(const std::string &content)
        {
            return ParseNtProcessApi(content);
        }

        bool PHNTDatabase::ParseNtSystemApi(const std::string &content)
        {
            return ParseNtProcessApi(content);
        }

        // PHNTEnhancedResolver implementation
        PHNTEnhancedResolver::PHNTEnhancedResolver()
            : AutomatedParamResolver()
        {
        }

        SyscallSignature PHNTEnhancedResolver::ResolveSyscallParameters(
            const std::string &function_name,
            uint32_t syscall_number,
            const uint8_t *stub_bytes,
            size_t stub_size,
            uintptr_t function_address)
        {

            // First, try PHNT database
            if (phnt_db_)
            {
                auto phnt_func = phnt_db_->LookupFunction(function_name);
                if (phnt_func.has_value())
                {
                    LOG_DEBUG("Found " + function_name + " in PHNT database");
                    return phnt_db_->ConvertToSignature(phnt_func.value());
                }
            }

            // Fall back to automated parameter resolution
            LOG_DEBUG("Falling back to automated resolution for " + function_name);
            return AutomatedParamResolver::ResolveSyscallParameters(
                function_name, syscall_number, stub_bytes, stub_size, function_address);
        }

    }
}
