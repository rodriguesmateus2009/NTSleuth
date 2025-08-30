// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include "analysis/automated_param_resolver.h"

namespace windows_arm64_analyzer
{
    namespace analysis
    {

        // Forward declaration
        class PHNTDatabase;

        // Global PHNT database initialization
        bool InitializePHNTDatabase();

        // Represents a parsed parameter from PHNT headers
        struct PHNTParameter
        {
            std::string name;        // Parameter name
            std::string type;        // Full type string (e.g., "PHANDLE")
            std::string direction;   // _In_, _Out_, _Inout_, _In_opt_, etc.
            std::string description; // Parameter description from comments
            bool is_optional;        // Whether parameter can be NULL
            bool is_output;          // Whether it's an output parameter
            bool is_input;           // Whether it's an input parameter
            std::string annotations; // SAL annotations
            size_t size_hint;        // Size hint for buffers (if applicable)
        };

        // Represents a parsed function signature from PHNT
        struct PHNTFunction
        {
            std::string name;                      // Function name (e.g., "NtCreateProcessEx")
            std::string return_type;               // Return type (usually NTSTATUS)
            std::vector<PHNTParameter> parameters; // List of parameters
            std::string description;               // Function description from comments
            std::string source_file;               // Source file where defined
            size_t line_number;                    // Line number in source
            bool is_documented;                    // Whether function has documentation
        };

        // Main PHNT database class
        class PHNTDatabase
        {
        public:
            PHNTDatabase();
            ~PHNTDatabase();

            // Initialize database from online source or local cache
            bool Initialize(bool force_download = false);

            // Load database from a specific path
            bool LoadFromPath(const std::string &path);

            // Download latest PHNT headers from System Informer repository
            bool DownloadHeaders(const std::string &cache_dir = "cache/phnt");

            // Parse a single header file
            bool ParseHeaderFile(const std::string &file_path);

            // Parse all header files in a directory
            bool ParseAllHeaders(const std::string &directory);

            // Lookup a function by name
            std::optional<PHNTFunction> LookupFunction(const std::string &function_name) const;

            // Convert PHNT function to SyscallSignature for resolver
            SyscallSignature ConvertToSignature(const PHNTFunction &func) const;

            // Get all parsed functions
            const std::map<std::string, PHNTFunction> &GetAllFunctions() const { return functions_; }

            // Get statistics
            struct Statistics
            {
                size_t total_functions;
                size_t documented_functions;
                size_t total_parameters;
                std::map<std::string, size_t> type_frequency;
            };
            Statistics GetStatistics() const;

            // Export database to JSON
            bool ExportToJSON(const std::string &output_path) const;

            // Import database from JSON
            bool ImportFromJSON(const std::string &input_path);

        private:
            // Parse function declaration from C code
            std::optional<PHNTFunction> ParseFunctionDeclaration(
                const std::string &declaration,
                const std::string &preceding_comment,
                const std::string &source_file,
                size_t line_number);

            // Extract parameter information from declaration
            std::vector<PHNTParameter> ParseParameters(const std::string &params_str);

            // Parse SAL annotations (_In_, _Out_, etc.)
            void ParseSALAnnotations(PHNTParameter &param, const std::string &annotations);

            // Extract description from Doxygen-style comments
            std::map<std::string, std::string> ParseDoxygenComment(const std::string &comment);

            // Convert PHNT type to ParamType enum
            ParamType ConvertToParamType(const std::string &type_str) const;

            // Clean and normalize type strings
            std::string NormalizeType(const std::string &type) const;

            // Download file from URL
            bool DownloadFile(const std::string &url, const std::string &output_path);

            // Parse specific PHNT headers
            bool ParseNtProcessApi(const std::string &content);
            bool ParseNtFileApi(const std::string &content);
            bool ParseNtMemoryApi(const std::string &content);
            bool ParseNtThreadApi(const std::string &content);
            bool ParseNtRegistryApi(const std::string &content);
            bool ParseNtSecurityApi(const std::string &content);
            bool ParseNtSystemApi(const std::string &content);

        private:
            std::map<std::string, PHNTFunction> functions_;
            std::string cache_directory_;
            bool initialized_;

            // URLs for System Informer PHNT headers
            static constexpr const char *PHNT_BASE_URL =
                "https://raw.githubusercontent.com/winsiderss/systeminformer/master/phnt/include/";

            // List of important PHNT header files
            static const std::vector<std::string> PHNT_HEADERS;
        };

        // Helper class for parsing C function declarations
        class CFunctionParser
        {
        public:
            struct ParsedFunction
            {
                std::string return_type;
                std::string calling_convention;
                std::string name;
                std::vector<std::pair<std::string, std::string>> parameters; // (type, name)
            };

            static std::optional<ParsedFunction> Parse(const std::string &declaration);

        private:
            static std::string ExtractReturnType(const std::string &decl, size_t &pos);
            static std::string ExtractCallingConvention(const std::string &decl, size_t &pos);
            static std::string ExtractFunctionName(const std::string &decl, size_t &pos);
            static std::vector<std::pair<std::string, std::string>> ExtractParameters(
                const std::string &params_str);
        };

        // Integration with AutomatedParamResolver
        class PHNTEnhancedResolver : public AutomatedParamResolver
        {
        public:
            PHNTEnhancedResolver();

            // Override to use PHNT database first
            SyscallSignature ResolveSyscallParameters(
                const std::string &function_name,
                uint32_t syscall_number,
                const uint8_t *stub_bytes,
                size_t stub_size,
                uintptr_t function_address = 0);

            // Set PHNT database
            void SetDatabase(std::shared_ptr<PHNTDatabase> db) { phnt_db_ = db; }

        private:
            std::shared_ptr<PHNTDatabase> phnt_db_;
        };

    }
}
