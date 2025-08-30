// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <fstream>
#include <iostream>

namespace WinSyscall
{

    enum class LogLevel
    {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Critical = 4,
        None = 5
    };

    class Logger
    {
    public:
        static Logger &Instance();

        // Configure logging
        void SetLogLevel(LogLevel level);
        void SetLogFile(const std::string &path);
        void EnableConsoleOutput(bool enable);
        void EnableFileOutput(bool enable);
        void EnableTimestamp(bool enable);

        // Logging methods
        void Debug(const std::string &message);
        void Info(const std::string &message);
        void Warning(const std::string &message);
        void Error(const std::string &message);
        void Critical(const std::string &message);

        // Formatted logging
        template <typename... Args>
        void DebugF(const std::string &format, Args... args);

        template <typename... Args>
        void InfoF(const std::string &format, Args... args);

        template <typename... Args>
        void WarningF(const std::string &format, Args... args);

        template <typename... Args>
        void ErrorF(const std::string &format, Args... args);

        // Flush logs
        void Flush();

    private:
        Logger();
        ~Logger();
        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;

        void Log(LogLevel level, const std::string &message);
        std::string GetTimestamp() const;
        std::string GetLogLevelString(LogLevel level) const;
        std::string FormatMessage(const std::string &format, ...);

        LogLevel log_level_ = LogLevel::Info;
        bool console_output_ = true;
        bool file_output_ = false;
        bool timestamp_enabled_ = true;
        std::string log_file_path_;
        std::ofstream log_file_;
        std::mutex mutex_;
    };

// Convenience macros
#define LOG_DEBUG(msg) WinSyscall::Logger::Instance().Debug(msg)
#define LOG_INFO(msg) WinSyscall::Logger::Instance().Info(msg)
#define LOG_WARNING(msg) WinSyscall::Logger::Instance().Warning(msg)
#define LOG_ERROR(msg) WinSyscall::Logger::Instance().Error(msg)
#define LOG_CRITICAL(msg) WinSyscall::Logger::Instance().Critical(msg)

}
