// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <exception>

namespace WinSyscall
{

    // Base exception class for all tool errors
    class ExtractorException : public std::exception
    {
    public:
        explicit ExtractorException(const std::string &message)
            : message_(message) {}

        const char *what() const noexcept override
        {
            return message_.c_str();
        }

        const std::string &GetMessage() const
        {
            return message_;
        }

    protected:
        std::string message_;
    };

    // Module loading errors
    class ModuleException : public ExtractorException
    {
    public:
        explicit ModuleException(const std::string &message)
            : ExtractorException("Module Error: " + message) {}
    };

    // Symbol parsing errors
    class SymbolException : public ExtractorException
    {
    public:
        explicit SymbolException(const std::string &message)
            : ExtractorException("Symbol Error: " + message) {}
    };

    // Disassembly errors
    class DisassemblyException : public ExtractorException
    {
    public:
        explicit DisassemblyException(const std::string &message)
            : ExtractorException("Disassembly Error: " + message) {}
    };

    // File I/O errors
    class FileException : public ExtractorException
    {
    public:
        explicit FileException(const std::string &message)
            : ExtractorException("File Error: " + message) {}
    };

    // Network/Download errors
    class NetworkException : public ExtractorException
    {
    public:
        explicit NetworkException(const std::string &message)
            : ExtractorException("Network Error: " + message) {}
    };

    // Configuration errors
    class ConfigException : public ExtractorException
    {
    public:
        explicit ConfigException(const std::string &message)
            : ExtractorException("Configuration Error: " + message) {}
    };

    // Error codes for non-exception error handling
    enum class ErrorCode
    {
        Success = 0,
        InvalidParameter,
        FileNotFound,
        AccessDenied,
        OutOfMemory,
        InvalidFormat,
        SymbolNotFound,
        NetworkError,
        NotImplemented,
        Unknown
    };

    // Convert error code to string
    inline std::string ErrorCodeToString(ErrorCode code)
    {
        switch (code)
        {
        case ErrorCode::Success:
            return "Success";
        case ErrorCode::InvalidParameter:
            return "Invalid parameter";
        case ErrorCode::FileNotFound:
            return "File not found";
        case ErrorCode::AccessDenied:
            return "Access denied";
        case ErrorCode::OutOfMemory:
            return "Out of memory";
        case ErrorCode::InvalidFormat:
            return "Invalid format";
        case ErrorCode::SymbolNotFound:
            return "Symbol not found";
        case ErrorCode::NetworkError:
            return "Network error";
        case ErrorCode::NotImplemented:
            return "Not implemented";
        case ErrorCode::Unknown:
        default:
            return "Unknown error";
        }
    }

    // Result wrapper for functions that can fail
    template <typename T>
    class Result
    {
    public:
        Result(T value) : value_(std::move(value)), has_value_(true) {}
        Result(ErrorCode error, const std::string &message = "")
            : error_(error), error_message_(message), has_value_(false) {}

        bool IsSuccess() const { return has_value_; }
        bool IsError() const { return !has_value_; }

        const T &Value() const { return value_; }
        T &Value() { return value_; }

        ErrorCode GetError() const { return error_; }
        std::string GetErrorMessage() const
        {
            if (error_message_.empty())
            {
                return ErrorCodeToString(error_);
            }
            return error_message_;
        }

    private:
        T value_{};
        ErrorCode error_ = ErrorCode::Success;
        std::string error_message_;
        bool has_value_ = false;
    };

}
