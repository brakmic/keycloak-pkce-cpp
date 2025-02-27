/**
 * @file logging.hpp
 * @brief Centralized logging facility
 * 
 * Provides a unified logging interface using spdlog. Supports multiple log levels,
 * formatted output, and both file and console logging. Thread-safe implementation
 * with configurable log patterns and levels.
 */

 #pragma once
 #include <spdlog/spdlog.h>
 #include <spdlog/common.h>
 #include <spdlog/sinks/stdout_color_sinks.h>
 #include <memory>
 #include <string>
 #include <string_view>
 #include <unordered_map>
 #include <iostream>
 
 namespace logging {
 
/**
 * @class Logger
 * @brief Thread-safe static logging interface wrapping spdlog
 * 
 * Provides a simplified interface for logging operations with support for:
 * - Multiple severity levels
 * - Format string support via fmt library
 * - Colored console output
 * - Configurable log patterns
 * - Thread-safe logging operations
 */
 class Logger {
 public:
    /**
     * @brief Logging severity levels
     * 
     * Defines the available logging levels in order of increasing severity.
     * Maps directly to spdlog levels while providing a library-specific interface.
     */
    enum class Level {
        Trace,      ///< Verbose debug information
        Debug,      ///< Debugging information
        Info,       ///< General information
        Warning,    ///< Warning messages
        Error,      ///< Error conditions
        Critical,   ///< Critical conditions
        Off         ///< Disable logging
    };
 
    /**
     * @brief Initializes the logging system
     * @param pattern Log message format pattern
     * 
     * Pattern format follows spdlog syntax:
     * - %Y-%m-%d %H:%M:%S.%e : Timestamp
     * - %^%l%$ : Colored log level
     * - %t : Thread ID
     * - %v : Actual message
     */
    static void init(const std::string& pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v") {
        try {
            if (!spdlog::get("console")) {
                auto logger = spdlog::stdout_color_mt("console");
                logger->set_pattern(pattern);
                logger->flush_on(spdlog::level::trace);
                spdlog::set_default_logger(logger);
            }
        }
        catch (const spdlog::spdlog_ex& ex) {
            std::cerr << "Logger initialization failed: " << ex.what() << std::endl;
        }
    }

    /**
     * @brief Sets the global logging level
     * @param level Minimum severity level to log
     */
    static void setLevel(Level level) {
        spdlog::set_level(toSpdlogLevel(level));
    }

    /**
     * @brief Logs a debug message
     * @param fmt Format string (fmt library syntax)
     * @param args Format arguments
     */
    template<typename... Args>
    static void debug(fmt::format_string<Args...> fmt, Args&&... args) {
        spdlog::debug(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs an info message
     * @param fmt Format string (fmt library syntax)
     * @param args Format arguments
     */
    template<typename... Args>
    static void info(fmt::format_string<Args...> fmt, Args&&... args) {
        spdlog::info(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a warning message
     * @param fmt Format string (fmt library syntax)
     * @param args Format arguments
     */
    template<typename... Args>
    static void warn(fmt::format_string<Args...> fmt, Args&&... args) {
        spdlog::warn(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs an error message
     * @param fmt Format string (fmt library syntax)
     * @param args Format arguments
     */
    template<typename... Args>
    static void error(fmt::format_string<Args...> fmt, Args&&... args) {
        spdlog::error(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Logs a critical message
     * @param fmt Format string (fmt library syntax)
     * @param args Format arguments
     */
    template<typename... Args>
    static void critical(fmt::format_string<Args...> fmt, Args&&... args) {
        spdlog::critical(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Converts string log level to enum
     * @param level Log level as string ("trace", "debug", etc.)
     * @return Corresponding Level enum value, defaults to Info if invalid
     */
    static Level fromString(const std::string& level) {
        static const std::unordered_map<std::string, Level> levelMap = {
            {"trace", Level::Trace},
            {"debug", Level::Debug},
            {"info", Level::Info},
            {"warning", Level::Warning},
            {"error", Level::Error},
            {"critical", Level::Critical},
            {"off", Level::Off}
        };

        auto it = levelMap.find(level);
        return it != levelMap.end() ? it->second : Level::Info;
    }
 
 private:
    /**
     * @brief Converts library log level to spdlog level
     * @param level Library-specific log level
     * @return Corresponding spdlog level
     */
    static spdlog::level::level_enum toSpdlogLevel(Level level) {
        switch (level) {
            case Level::Trace: return spdlog::level::trace;
            case Level::Debug: return spdlog::level::debug;
            case Level::Info: return spdlog::level::info;
            case Level::Warning: return spdlog::level::warn;
            case Level::Error: return spdlog::level::err;
            case Level::Critical: return spdlog::level::critical;
            case Level::Off: return spdlog::level::off;
        }
        return spdlog::level::info;
    }
 };
 
 } // namespace logging
