// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <optional>
#include <functional>
#include "symbols/syscall_info.h"

namespace windows_arm64_analyzer
{
    namespace analysis
    {

        // Parameter type inference based on patterns
        enum class ParamType
        {
            Unknown,
            Handle,           // HANDLE types
            Pointer,          // Pointer to structure/buffer
            Integer,          // Integer value
            UnicodeString,    // UNICODE_STRING*
            AccessMask,       // Access rights mask
            ObjectAttributes, // OBJECT_ATTRIBUTES*
            IoStatusBlock,    // IO_STATUS_BLOCK*
            LargeInteger,     // LARGE_INTEGER*
            Boolean,          // BOOLEAN
            Ulong,            // ULONG
            Size,             // SIZE_T
            Status            // NTSTATUS
        };

        // Detected parameter information
        struct DetectedParameter
        {
            size_t index;            // Parameter index (0-based)
            ParamType type;          // Inferred type
            std::string type_name;   // Type name string
            std::string name;        // Parameter name (if detected)
            bool is_optional;        // Whether parameter can be NULL
            bool is_output;          // Whether it's an output parameter
            bool is_input = true;    // Whether it's an input parameter (default true)
            size_t size_hint;        // Size hint for buffers
            std::string description; // Parameter description
        };

        // Syscall signature detection result
        struct SyscallSignature
        {
            std::string function_name;
            std::string return_type;
            std::vector<DetectedParameter> parameters;
            size_t parameter_count;
            bool is_verified;             // Whether signature was verified through testing
            double confidence;            // Confidence score (0.0 - 1.0)
            std::string detection_method; // Method used for detection
        };

        // Detection methods used
        enum class DetectionMethod
        {
            AssemblyAnalysis,  // Assembly code pattern analysis
            DynamicTracing,    // Runtime tracing
            HeuristicMatching, // Pattern matching with known syscalls
            FuzzTesting,       // Systematic fuzzing
            RegisterAnalysis,  // Register usage analysis
            StackAnalysis,     // Stack frame analysis
            CrossReference,    // Cross-referencing with known patterns
            Combined           // Multiple methods combined
        };

        class AutomatedParamResolver
        {
        public:
            AutomatedParamResolver();
            ~AutomatedParamResolver();

            // Main resolution function
            SyscallSignature ResolveSyscallParameters(
                const std::string &function_name,
                uint32_t syscall_number,
                const uint8_t *stub_bytes,
                size_t stub_size,
                uintptr_t function_address = 0);

            // Batch resolution for all syscalls
            std::map<std::string, SyscallSignature> ResolveAllSyscalls(
                const std::vector<symbols::SyscallInfo> &syscalls);

            // Set confidence threshold (0.0 - 1.0)
            void SetConfidenceThreshold(double threshold) { confidence_threshold_ = threshold; }

            // Enable/disable specific detection methods
            void EnableMethod(DetectionMethod method, bool enable = true);

            // Get statistics about resolution success
            struct ResolutionStats
            {
                size_t total_syscalls;
                size_t resolved_fully;
                size_t resolved_partially;
                size_t failed;
                double average_confidence;
                std::map<DetectionMethod, size_t> method_usage;
            };
            ResolutionStats GetStatistics() const { return stats_; }

        private:
            // Assembly pattern analysis
            SyscallSignature AnalyzeAssemblyPattern(
                const std::string &function_name,
                const uint8_t *stub_bytes,
                size_t stub_size);

            // Dynamic tracing using debug API
            SyscallSignature TraceSyscallDynamically(
                const std::string &function_name,
                uint32_t syscall_number);

            // Heuristic pattern matching
            SyscallSignature MatchHeuristicPatterns(
                const std::string &function_name,
                uint32_t syscall_number);

            // Register usage analysis for ARM64
            SyscallSignature AnalyzeRegisterUsage(
                const uint8_t *stub_bytes,
                size_t stub_size);

            // Stack frame analysis
            SyscallSignature AnalyzeStackFrame(
                uintptr_t function_address);

            // Cross-reference with known patterns
            SyscallSignature CrossReferencePatterns(
                const std::string &function_name);

            // Combine results from multiple methods
            SyscallSignature CombineResults(
                const std::vector<SyscallSignature> &candidates);

            // Parameter type inference
            ParamType InferParameterType(
                const std::string &pattern,
                size_t position,
                const std::vector<uint8_t> &context);

            // Verify signature through testing
            bool VerifySignature(
                const SyscallSignature &signature,
                uint32_t syscall_number);

            // Known syscall patterns database
            void InitializeKnownPatterns();

            // ARM64 specific analysis
            std::vector<DetectedParameter> AnalyzeARM64Parameters(
                const uint8_t *code,
                size_t size);

            // x64 specific analysis
            std::vector<DetectedParameter> AnalyzeX64Parameters(
                const uint8_t *code,
                size_t size);

        private:
            double confidence_threshold_;
            std::map<DetectionMethod, bool> enabled_methods_;
            ResolutionStats stats_;

            // Pattern database
            struct KnownPattern
            {
                std::string name_pattern; // Regex for function name
                std::vector<ParamType> param_types;
                std::string return_type;
                double confidence_boost;
            };
            std::vector<KnownPattern> known_patterns_;

            // Cache for resolved signatures
            std::map<std::string, SyscallSignature> signature_cache_;

            // Debug tracer handle
            class DebugTracer;
            std::unique_ptr<DebugTracer> debug_tracer_;
        };

        // Helper class for syscall fuzzing
        class SyscallFuzzer
        {
        public:
            struct FuzzResult
            {
                bool crashed;
                NTSTATUS status;
                size_t param_count_hint;
                std::vector<ParamType> type_hints;
            };

            FuzzResult FuzzSyscall(
                uint32_t syscall_number,
                size_t max_params = 20);

        private:
            // Safe syscall invocation for testing
            NTSTATUS InvokeSyscallSafely(
                uint32_t syscall_number,
                void **params,
                size_t param_count);
        };

        // Pattern recognition engine
        class PatternEngine
        {
        public:
            // Common syscall patterns
            static constexpr const char *HANDLE_PATTERN = R"((?i)h[a-z]*handle|handle)";
            static constexpr const char *POINTER_PATTERN = R"((?i)p[a-z]+|lp[a-z]+|buffer)";
            static constexpr const char *STRING_PATTERN = R"((?i)string|str|name|path)";
            static constexpr const char *SIZE_PATTERN = R"((?i)size|length|count|cb[a-z]*)";
            static constexpr const char *ACCESS_PATTERN = R"((?i)access|desired|mask|rights)";

            // Analyze function name for parameter hints
            static std::vector<ParamType> InferFromName(const std::string &function_name);

            // Match against common patterns
            static ParamType MatchPattern(const std::string &text);
        };

    }
}
