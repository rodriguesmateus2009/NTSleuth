// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "utils/logger.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cstdarg>
#include <sstream>

namespace WinSyscall
{

    Logger &Logger::Instance()
    {
        static Logger instance;
        return instance;
    }

    Logger::Logger()
    {
    }

    Logger::~Logger()
    {
        if (log_file_.is_open())
        {
            log_file_.close();
        }
    }

    void Logger::SetLogLevel(LogLevel level)
    {
        log_level_ = level;
    }

    void Logger::SetLogFile(const std::string &path)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (log_file_.is_open())
        {
            log_file_.close();
        }

        log_file_path_ = path;
        if (!path.empty())
        {
            log_file_.open(path, std::ios::out | std::ios::app);
            file_output_ = log_file_.is_open();
        }
    }

    void Logger::EnableConsoleOutput(bool enable)
    {
        console_output_ = enable;
    }

    void Logger::EnableFileOutput(bool enable)
    {
        file_output_ = enable && log_file_.is_open();
    }

    void Logger::EnableTimestamp(bool enable)
    {
        timestamp_enabled_ = enable;
    }

    void Logger::Debug(const std::string &message)
    {
        Log(LogLevel::Debug, message);
    }

    void Logger::Info(const std::string &message)
    {
        Log(LogLevel::Info, message);
    }

    void Logger::Warning(const std::string &message)
    {
        Log(LogLevel::Warning, message);
    }

    void Logger::Error(const std::string &message)
    {
        Log(LogLevel::Error, message);
    }

    void Logger::Critical(const std::string &message)
    {
        Log(LogLevel::Critical, message);
    }

    template <typename... Args>
    void Logger::DebugF(const std::string &format, Args... args)
    {
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        Debug(buffer);
    }

    template <typename... Args>
    void Logger::InfoF(const std::string &format, Args... args)
    {
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        Info(buffer);
    }

    template <typename... Args>
    void Logger::WarningF(const std::string &format, Args... args)
    {
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        Warning(buffer);
    }

    template <typename... Args>
    void Logger::ErrorF(const std::string &format, Args... args)
    {
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        Error(buffer);
    }

    void Logger::Flush()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (console_output_)
        {
            std::cout.flush();
            std::cerr.flush();
        }

        if (file_output_ && log_file_.is_open())
        {
            log_file_.flush();
        }
    }

    void Logger::Log(LogLevel level, const std::string &message)
    {
        if (level < log_level_)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        std::string formatted_message;

        if (timestamp_enabled_)
        {
            formatted_message = "[" + GetTimestamp() + "] ";
        }

        formatted_message += "[" + GetLogLevelString(level) + "] " + message;

        if (console_output_)
        {
            if (level >= LogLevel::Error)
            {
                std::cerr << formatted_message << std::endl;
            }
            else
            {
                std::cout << formatted_message << std::endl;
            }
        }

        if (file_output_ && log_file_.is_open())
        {
            log_file_ << formatted_message << std::endl;
        }
    }

    std::string Logger::GetTimestamp() const
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::stringstream ss;
        struct tm time_info;
#ifdef _WIN32
        localtime_s(&time_info, &time_t);
#else
        localtime_r(&time_t, &time_info);
#endif
        ss << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();

        return ss.str();
    }

    std::string Logger::GetLogLevelString(LogLevel level) const
    {
        switch (level)
        {
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARN";
        case LogLevel::Error:
            return "ERROR";
        case LogLevel::Critical:
            return "CRIT";
        default:
            return "UNKNOWN";
        }
    }

}
