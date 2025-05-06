/**
 * XLog - A lightweight, cross-platform C++ logging library
 * Suitable for desktop and embedded systems
 * 
 * Features:
 * - Multiple logging levels (DEBUG, INFO, WARN, ERROR, FATAL)
 * - Multiple sink types (console, file with rotation, custom sinks)
 * - Thread-safe operations
 * - Minimal external dependencies
 * - Configurable formatting
 * - Conditional compilation for embedded systems
 * - JSON output format
 */

#ifndef XLOG_H
#define XLOG_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <filesystem>
#include <functional>
#include <atomic>
#include <unordered_map>

#ifdef XLOG_EMBEDDED
    // Minimal version for embedded systems
    #define XLOG_NO_FILESYSTEM
    #define XLOG_MINIMAL_FORMAT
#endif

namespace xlog {

// Forward declarations
class Sink;
class Logger;

/**
 * Logging levels
 */
enum class Level {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL,
    OFF
};

/**
 * Convert Level to string
 */
inline std::string level_to_string(Level level) {
    switch (level) {
        case Level::DEBUG: return "DEBUG";
        case Level::INFO:  return "INFO";
        case Level::WARN:  return "WARN";
        case Level::ERROR: return "ERROR";
        case Level::FATAL: return "FATAL";
        case Level::OFF:   return "OFF";
        default:           return "UNKNOWN";
    }
}

/**
 * Convert string to Level
 */
inline Level string_to_level(const std::string& str) {
    if (str == "DEBUG") return Level::DEBUG;
    if (str == "INFO")  return Level::INFO;
    if (str == "WARN")  return Level::WARN;
    if (str == "ERROR") return Level::ERROR;
    if (str == "FATAL") return Level::FATAL;
    if (str == "OFF")   return Level::OFF;
    return Level::INFO; // Default
}

/**
 * Log record structure
 */
struct LogRecord {
    std::chrono::system_clock::time_point time;
    Level level;
    std::string message;
    std::string logger_name;
};

/**
 * Base class for all sinks
 */
class Sink {
public:
    Sink(Level level = Level::DEBUG) : level_(level) {}
    virtual ~Sink() = default;
    
    virtual void log(const LogRecord& record) = 0;
    
    void set_level(Level level) { level_ = level; }
    Level level() const { return level_; }
    
    bool should_log(Level msg_level) const {
        return msg_level >= level_;
    }
    
protected:
    Level level_;
};

/**
 * JSON formatter for log records
 */
class JsonFormatter {
public:
    static std::string format(const LogRecord& record) {
        std::stringstream ss;
        auto time_t = std::chrono::system_clock::to_time_t(record.time);
        
        std::tm tm = {};
#if defined(_WIN32)
        localtime_s(&tm, &time_t);
#else
        localtime_r(&time_t, &tm);
#endif
        
        char time_buf[32];
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", &tm);
        
        ss << "{";
        ss << "\"timestamp\":\"" << time_buf << "\",";
        ss << "\"level\":\"" << escape_json(level_to_string(record.level)) << "\",";
        ss << "\"logger\":\"" << escape_json(record.logger_name) << "\",";
        ss << "\"message\":\"" << escape_json(record.message) << "\"";
        ss << "}";
        
        return ss.str();
    }
    
private:
    static std::string escape_json(const std::string& input) {
        std::string output;
        output.reserve(input.length() * 2); // Reserve space to avoid reallocations
        
        for (char c : input) {
            switch (c) {
                case '\"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '/':  output += "\\/"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 32) {
                        char hex[7];
                        snprintf(hex, sizeof(hex), "\\u%04x", c);
                        output += hex;
                    } else {
                        output += c;
                    }
                    break;
            }
        }
        
        return output;
    }
};

/**
 * Console sink (stdout/stderr)
 */
class ConsoleSink : public Sink {
public:
    enum class OutputType {
        Stdout,
        Stderr
    };
    
    ConsoleSink(OutputType type = OutputType::Stdout, Level level = Level::DEBUG)
        : Sink(level), type_(type) {}
    
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        
        std::string formatted = format(record);
        if (type_ == OutputType::Stdout) {
            std::cout << formatted << std::endl;
        } else {
            std::cerr << formatted << std::endl;
        }
    }
    
private:
    std::string format(const LogRecord& record) {
        std::stringstream ss;
        auto time_t = std::chrono::system_clock::to_time_t(record.time);
        
#ifndef XLOG_MINIMAL_FORMAT
        std::tm tm = {};
#if defined(_WIN32)
        localtime_s(&tm, &time_t);
#else
        localtime_r(&time_t, &tm);
#endif
        
        ss << "["
           << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
           << "] ["
           << record.logger_name
           << "] ["
           << level_to_string(record.level)
           << "]: "
           << record.message;
#else
        // Minimal format for embedded systems
        ss << "["
           << level_to_string(record.level)
           << "] "
           << record.message;
#endif
        
        return ss.str();
    }
    
    OutputType type_;
};

/**
 * JSON console sink that formats log records as JSON
 */
class JsonConsoleSink : public Sink {
public:
    enum class OutputType {
        Stdout,
        Stderr
    };
    
    JsonConsoleSink(OutputType type = OutputType::Stdout, Level level = Level::DEBUG)
        : Sink(level), type_(type) {}
    
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        
        std::string formatted = JsonFormatter::format(record);
        if (type_ == OutputType::Stdout) {
            std::cout << formatted << std::endl;
        } else {
            std::cerr << formatted << std::endl;
        }
    }
    
private:
    OutputType type_;
};

#ifndef XLOG_NO_FILESYSTEM
/**
 * File sink with rotation capability
 */
class FileSink : public Sink {
public:
    FileSink(const std::string& base_filename, 
             Level level = Level::DEBUG,
             size_t max_size = 10 * 1024 * 1024,  // 10 MB default
             int max_files = 5)
        : Sink(level),
          base_filename_(base_filename),
          max_size_(max_size),
          max_files_(max_files),
          current_size_(0) {
        open_file();
    }
    
    ~FileSink() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.close();
        }
    }
    
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        
        std::string formatted = format(record);
        
        std::lock_guard<std::mutex> lock(mutex_);
        if (!file_.is_open()) {
            open_file();
        }
        
        file_ << formatted << std::endl;
        current_size_ += formatted.size() + 1; // +1 for newline
        
        if (current_size_ >= max_size_) {
            rotate_log();
        }
    }
    
private:
    std::string format(const LogRecord& record) {
        std::stringstream ss;
        auto time_t = std::chrono::system_clock::to_time_t(record.time);
        
        std::tm tm = {};
#if defined(_WIN32)
        localtime_s(&tm, &time_t);
#else
        localtime_r(&time_t, &tm);
#endif
        
        ss << "["
           << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") 
           << "] ["
           << record.logger_name
           << "] ["
           << level_to_string(record.level)
           << "]: "
           << record.message;
        
        return ss.str();
    }
    
    void open_file() {
        file_.open(base_filename_, std::ios::app);
        if (file_.is_open()) {
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
    }
    
    void rotate_log() {
        if (file_.is_open()) {
            file_.close();
        }
        
        // Remove oldest file if it exists
        if (max_files_ > 0) {
            std::string oldest_file = base_filename_ + "." + std::to_string(max_files_);
            std::filesystem::remove(oldest_file);
            
            // Shift existing log files
            for (int i = max_files_ - 1; i >= 1; --i) {
                std::string old_name = base_filename_ + "." + std::to_string(i);
                std::string new_name = base_filename_ + "." + std::to_string(i + 1);
                
                if (std::filesystem::exists(old_name)) {
                    std::filesystem::rename(old_name, new_name);
                }
            }
            
            // Rename current log file
            std::string backup = base_filename_ + ".1";
            std::filesystem::rename(base_filename_, backup);
        }
        
        // Open new log file
        open_file();
    }
    
    std::string base_filename_;
    size_t max_size_;
    int max_files_;
    size_t current_size_;
    std::ofstream file_;
    std::mutex mutex_;
};

/**
 * JSON file sink that writes log records as JSON to a file
 */
class JsonFileSink : public Sink {
public:
    JsonFileSink(const std::string& base_filename, 
                Level level = Level::DEBUG,
                size_t max_size = 10 * 1024 * 1024,  // 10 MB default
                int max_files = 5)
        : Sink(level),
          base_filename_(base_filename),
          max_size_(max_size),
          max_files_(max_files),
          current_size_(0) {
        open_file();
    }
    
    ~JsonFileSink() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.close();
        }
    }
    
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        
        std::string formatted = JsonFormatter::format(record);
        
        std::lock_guard<std::mutex> lock(mutex_);
        if (!file_.is_open()) {
            open_file();
        }
        
        file_ << formatted << std::endl;
        current_size_ += formatted.size() + 1; // +1 for newline
        
        if (current_size_ >= max_size_) {
            rotate_log();
        }
    }
    
private:
    void open_file() {
        file_.open(base_filename_, std::ios::app);
        if (file_.is_open()) {
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
    }
    
    void rotate_log() {
        if (file_.is_open()) {
            file_.close();
        }
        
        // Remove oldest file if it exists
        if (max_files_ > 0) {
            std::string oldest_file = base_filename_ + "." + std::to_string(max_files_);
            std::filesystem::remove(oldest_file);
            
            // Shift existing log files
            for (int i = max_files_ - 1; i >= 1; --i) {
                std::string old_name = base_filename_ + "." + std::to_string(i);
                std::string new_name = base_filename_ + "." + std::to_string(i + 1);
                
                if (std::filesystem::exists(old_name)) {
                    std::filesystem::rename(old_name, new_name);
                }
            }
            
            // Rename current log file
            std::string backup = base_filename_ + ".1";
            std::filesystem::rename(base_filename_, backup);
        }
        
        // Open new log file
        open_file();
    }
    
    std::string base_filename_;
    size_t max_size_;
    int max_files_;
    size_t current_size_;
    std::ofstream file_;
    std::mutex mutex_;
};
#endif // XLOG_NO_FILESYSTEM

/**
 * Custom sink using a callback function
 */
class CallbackSink : public Sink {
public:
    using Callback = std::function<void(const LogRecord&)>;
    
    CallbackSink(Callback callback, Level level = Level::DEBUG)
        : Sink(level), callback_(callback) {}
    
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        callback_(record);
    }
    
private:
    Callback callback_;
};

/**
 * Logger class
 */
class Logger {
public:
    Logger(const std::string& name, Level level = Level::DEBUG)
        : name_(name), level_(level) {}
    
    template<typename SinkPtr>
    void add_sink(SinkPtr sink) {
        std::lock_guard<std::mutex> lock(mutex_);
        sinks_.push_back(std::move(sink));
    }
    
    void set_level(Level level) {
        level_ = level;
    }
    
    Level level() const {
        return level_;
    }
    
    void log(Level level, const std::string& message) {
        if (level < level_) return;
        
        LogRecord record{
            std::chrono::system_clock::now(),
            level,
            message,
            name_
        };
        
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& sink : sinks_) {
            sink->log(record);
        }
    }
    
    void debug(const std::string& message) {
        log(Level::DEBUG, message);
    }
    
    void info(const std::string& message) {
        log(Level::INFO, message);
    }
    
    void warn(const std::string& message) {
        log(Level::WARN, message);
    }
    
    void error(const std::string& message) {
        log(Level::ERROR, message);
    }
    
    void fatal(const std::string& message) {
        log(Level::FATAL, message);
    }
    
private:
    std::string name_;
    Level level_;
    std::vector<std::shared_ptr<Sink>> sinks_;
    std::mutex mutex_;
};

/**
 * LoggerRegistry for managing loggers
 */
class LoggerRegistry {
public:
    static LoggerRegistry& instance() {
        static LoggerRegistry registry;
        return registry;
    }
    
    std::shared_ptr<Logger> get_or_create(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = loggers_.find(name);
        if (it != loggers_.end()) {
            return it->second;
        }
        
        auto logger = std::make_shared<Logger>(name);
        loggers_[name] = logger;
        return logger;
    }
    
    void set_global_level(Level level) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : loggers_) {
            pair.second->set_level(level);
        }
    }
    
private:
    LoggerRegistry() = default;
    std::unordered_map<std::string, std::shared_ptr<Logger>> loggers_;
    std::mutex mutex_;
};

} // namespace xlog

// Convenient macros
#define XLOG_GET_LOGGER(name) xlog::LoggerRegistry::instance().get_or_create(name)

#define XLOG_DEBUG(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::DEBUG) { \
            std::ostringstream ss; \
            ss << message; \
            logger->debug(ss.str()); \
        } \
    } while(0)

#define XLOG_INFO(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::INFO) { \
            std::ostringstream ss; \
            ss << message; \
            logger->info(ss.str()); \
        } \
    } while(0)

#define XLOG_WARN(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::WARN) { \
            std::ostringstream ss; \
            ss << message; \
            logger->warn(ss.str()); \
        } \
    } while(0)

#define XLOG_ERROR(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::ERROR) { \
            std::ostringstream ss; \
            ss << message; \
            logger->error(ss.str()); \
        } \
    } while(0)

#define XLOG_FATAL(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::FATAL) { \
            std::ostringstream ss; \
            ss << message; \
            logger->fatal(ss.str()); \
        } \
    } while(0)

#endif // XLOG_H
