/**
 * @file xlog.h
 * @brief A lightweight, cross-platform C++ logging library
 * @author DatanoiseTV
 * @date 2025-05-06
 * 
 * XLog is a flexible logging library suitable for both desktop and embedded systems.
 * It provides multiple logging levels, various output destinations, and thread-safety
 * with minimal external dependencies.
 * 
 * @details
 * Features include:
 * - Multiple logging levels (DEBUG, INFO, WARN, ERROR, FATAL)
 * - Multiple sink types (console, file with rotation, custom sinks)
 * - Thread-safe operations
 * - Minimal external dependencies
 * - Configurable formatting
 * - Conditional compilation for embedded systems
 * - JSON output format
 * - Syslog integration (local and remote)
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

/**
 * @def XLOG_EMBEDDED
 * @brief Define for embedded systems with limited resources
 * 
 * When defined, this macro activates resource-saving features
 * for embedded systems, including disabling filesystem operations
 * and using minimal formatting.
 */
#ifdef XLOG_EMBEDDED
    /**
     * @def XLOG_NO_FILESYSTEM
     * @brief Disable filesystem operations for embedded systems
     */
    #define XLOG_NO_FILESYSTEM
    
    /**
     * @def XLOG_MINIMAL_FORMAT
     * @brief Use minimal message formatting for embedded systems
     */
    #define XLOG_MINIMAL_FORMAT
#endif

/**
 * @def XLOG_SYSLOG_AVAILABLE
 * @brief Enables syslog integration on supported platforms
 * 
 * This is automatically defined on UNIX-based systems when
 * not in embedded mode.
 */
#ifndef XLOG_EMBEDDED
    #if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
        #define XLOG_SYSLOG_AVAILABLE
        #include <syslog.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <arpa/inet.h>
        #include <unistd.h>
        #include <netdb.h>
        #include <cstring> // For memset, memcpy
    #endif
#endif

/**
 * @namespace xlog
 * @brief Main namespace for the XLog library
 */
namespace xlog {

// Forward declarations
class Sink;
class Logger;

/**
 * @enum Level
 * @brief Logging severity levels
 * 
 * Defines the available logging levels in order of increasing severity.
 */
enum class Level {
    DEBUG,  /**< Detailed information, typically useful only when diagnosing problems */
    INFO,   /**< Confirmation that things are working as expected */
    WARN,   /**< Indication that something unexpected happened, or may happen in the near future */
    ERROR,  /**< Due to a more serious problem, the software has not been able to perform some function */
    FATAL,  /**< A very severe error event that will presumably lead the application to abort */
    OFF     /**< Special level used to disable logging */
};

/**
 * @brief Convert Level enum to string representation
 * @param level The logging level to convert
 * @return String representation of the level
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
 * @brief Convert string to Level enum
 * @param str String representation of the level
 * @return The corresponding logging level (defaults to INFO if not recognized)
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
 * @struct LogRecord
 * @brief Structure containing all information about a log entry
 * 
 * This structure is passed to sinks for output formatting and processing.
 */
struct LogRecord {
    std::chrono::system_clock::time_point time;  /**< Timestamp when the log record was created */
    Level level;                                 /**< Severity level of the log record */
    std::string message;                         /**< The log message content */
    std::string logger_name;                     /**< Name of the logger that created this record */
};

/**
 * @class Sink
 * @brief Base abstract class for all log output destinations
 * 
 * A sink is responsible for outputting log records to a specific destination
 * such as the console, a file, syslog, etc. Each sink can filter logs based on
 * their level.
 */
class Sink {
public:
    /**
     * @brief Constructor
     * @param level Minimum log level this sink will process
     */
    Sink(Level level = Level::DEBUG) : level_(level) {}
    
    /**
     * @brief Virtual destructor
     */
    virtual ~Sink() = default;
    
    /**
     * @brief Process a log record
     * 
     * This method must be implemented by derived classes to define
     * how log records are processed for a specific sink.
     * 
     * @param record The log record to process
     */
    virtual void log(const LogRecord& record) = 0;
    
    /**
     * @brief Set the minimum log level
     * @param level New minimum log level
     */
    void set_level(Level level) { level_ = level; }
    
    /**
     * @brief Get the current minimum log level
     * @return Current minimum level
     */
    Level level() const { return level_; }
    
    /**
     * @brief Check if a message with the given level should be logged
     * @param msg_level Level of the message to check
     * @return True if the message should be logged
     */
    bool should_log(Level msg_level) const {
        return msg_level >= level_;
    }
    
protected:
    Level level_;  /**< Minimum log level this sink will process */
};

/**
 * @class JsonFormatter
 * @brief Utility class for formatting log records as JSON
 */
class JsonFormatter {
public:
    /**
     * @brief Format a log record as JSON
     * @param record The log record to format
     * @return JSON representation of the log record
     */
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
    /**
     * @brief Escape special characters in a string for JSON
     * @param input String to escape
     * @return Escaped string safe for JSON
     */
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
 * @class ConsoleSink
 * @brief Sink that outputs log records to the console
 */
class ConsoleSink : public Sink {
public:
    /**
     * @enum OutputType
     * @brief Type of console output stream
     */
    enum class OutputType {
        Stdout,  /**< Standard output stream */
        Stderr   /**< Standard error stream */
    };
    
    /**
     * @brief Constructor
     * @param type Output stream type (stdout or stderr)
     * @param level Minimum log level this sink will process
     */
    ConsoleSink(OutputType type = OutputType::Stdout, Level level = Level::DEBUG)
        : Sink(level), type_(type) {}
    
    /**
     * @brief Process a log record by outputting to console
     * @param record The log record to process
     */
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
    /**
     * @brief Format a log record for console output
     * @param record The log record to format
     * @return Formatted log message
     */
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
    
    OutputType type_;  /**< Type of console output stream */
};

/**
 * @class JsonConsoleSink
 * @brief Console sink that outputs log records in JSON format
 */
class JsonConsoleSink : public Sink {
public:
    /**
     * @enum OutputType
     * @brief Type of console output stream
     */
    enum class OutputType {
        Stdout,  /**< Standard output stream */
        Stderr   /**< Standard error stream */
    };
    
    /**
     * @brief Constructor
     * @param type Output stream type (stdout or stderr)
     * @param level Minimum log level this sink will process
     */
    JsonConsoleSink(OutputType type = OutputType::Stdout, Level level = Level::DEBUG)
        : Sink(level), type_(type) {}
    
    /**
     * @brief Process a log record by outputting to console in JSON format
     * @param record The log record to process
     */
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
    OutputType type_;  /**< Type of console output stream */
};

#ifdef XLOG_SYSLOG_AVAILABLE
/**
 * @brief Convert XLog level to syslog priority
 * @param level XLog severity level
 * @return Corresponding syslog priority
 */
inline int xlog_level_to_syslog(Level level) {
    switch (level) {
        case Level::DEBUG: return LOG_DEBUG;
        case Level::INFO:  return LOG_INFO;
        case Level::WARN:  return LOG_WARNING;
        case Level::ERROR: return LOG_ERR;
        case Level::FATAL: return LOG_CRIT;
        default:           return LOG_NOTICE;
    }
}

/**
 * @class SyslogSink
 * @brief Sink that outputs log records to the local syslog service
 * 
 * Available only on UNIX-based systems when not in embedded mode.
 */
class SyslogSink : public Sink {
public:
    /**
     * @brief Constructor
     * @param ident Program identifier that appears in log messages
     * @param level Minimum log level this sink will process
     * @param facility Syslog facility to use
     */
    SyslogSink(const std::string& ident, Level level = Level::DEBUG,
              int facility = LOG_USER)
        : Sink(level), ident_(ident), opened_(false) {
        
        // Open syslog connection
        openlog(ident_.c_str(), LOG_PID | LOG_CONS, facility);
        opened_ = true;
    }
    
    /**
     * @brief Destructor
     * 
     * Closes the connection to syslog.
     */
    ~SyslogSink() {
        if (opened_) {
            closelog();
        }
    }
    
    /**
     * @brief Process a log record by sending it to syslog
     * @param record The log record to process
     */
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        
        int priority = xlog_level_to_syslog(record.level);
        syslog(priority, "%s", record.message.c_str());
    }
    
private:
    std::string ident_;  /**< Program identifier that appears in log messages */
    bool opened_;        /**< Flag indicating if syslog connection is open */
};

/**
 * @class RemoteSyslogSink
 * @brief Sink that sends log records to a remote syslog server via UDP
 * 
 * Implements RFC 5424 syslog protocol for remote logging.
 * Available only on UNIX-based systems when not in embedded mode.
 */
class RemoteSyslogSink : public Sink {
public:
    /**
     * @brief Constructor
     * @param host Remote syslog server hostname or IP address
     * @param port Remote syslog server port (default: 514)
     * @param app_name Application name to include in syslog messages
     * @param level Minimum log level this sink will process
     * @param facility Syslog facility to use
     */
    RemoteSyslogSink(const std::string& host, 
                     int port = 514,  // Standard syslog port
                     const std::string& app_name = "xlog",
                     Level level = Level::DEBUG,
                     int facility = LOG_USER)
        : Sink(level), 
          host_(host), 
          port_(port), 
          app_name_(app_name),
          facility_(facility),
          sock_(-1),
          hostname_("localhost") {
        
        // Initialize socket
        sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ < 0) {
            std::cerr << "Error creating UDP socket for remote syslog" << std::endl;
            return;
        }
        
        // Resolve remote host
        struct hostent* server = gethostbyname(host_.c_str());
        if (server == nullptr) {
            std::cerr << "Error resolving remote syslog host: " << host_ << std::endl;
            close(sock_);
            sock_ = -1;
            return;
        }
        
        // Setup server address
        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin_family = AF_INET;
        memcpy(&server_addr_.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr_.sin_port = htons(port_);
        
        // Get local hostname for syslog messages
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            hostname_ = hostname;
        }
    }
    
    /**
     * @brief Destructor
     * 
     * Closes the UDP socket.
     */
    ~RemoteSyslogSink() {
        if (sock_ >= 0) {
            close(sock_);
        }
    }
    
    /**
     * @brief Process a log record by sending it to a remote syslog server
     * @param record The log record to process
     */
    void log(const LogRecord& record) override {
        if (!should_log(record.level) || sock_ < 0) return;
        
        // Format according to RFC 5424 syslog protocol
        std::string syslog_msg = format_syslog_message(record);
        
        // Send to remote server
        sendto(sock_, syslog_msg.c_str(), syslog_msg.length(), 0,
               (struct sockaddr*)&server_addr_, sizeof(server_addr_));
    }
    
private:
    /**
     * @brief Format a log record according to RFC 5424 syslog protocol
     * @param record The log record to format
     * @return Formatted syslog message
     */
    std::string format_syslog_message(const LogRecord& record) {
        int priority = facility_ * 8 + xlog_level_to_syslog(record.level);
        
        // Get timestamp
        auto time_t = std::chrono::system_clock::to_time_t(record.time);
        std::tm tm = {};
#if defined(_WIN32)
        localtime_s(&tm, &time_t);
#else
        localtime_r(&time_t, &tm);
#endif
        
        char timestamp[32];
        std::strftime(timestamp, sizeof(timestamp), "%FT%T%z", &tm);
        
        // Construct syslog message with format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        std::stringstream ss;
        ss << "<" << priority << ">1 " // PRI and VERSION
           << timestamp << " "          // TIMESTAMP
           << hostname_ << " "          // HOSTNAME
           << app_name_ << " "          // APP-NAME
           << getpid() << " "           // PROCID
           << record.logger_name << " " // MSGID
           << "- "                      // STRUCTURED-DATA (none)
           << record.message;           // MSG
        
        return ss.str();
    }
    
    std::string host_;              /**< Remote syslog server hostname or IP */
    int port_;                      /**< Remote syslog server port */
    std::string app_name_;          /**< Application name for syslog messages */
    int facility_;                  /**< Syslog facility */
    int sock_;                      /**< UDP socket file descriptor */
    struct sockaddr_in server_addr_; /**< Server address structure */
    std::string hostname_;          /**< Local hostname for syslog messages */
};
#endif // XLOG_SYSLOG_AVAILABLE

#ifndef XLOG_NO_FILESYSTEM
/**
 * @class FileSink
 * @brief Sink that writes log records to a file with rotation capability
 */
class FileSink : public Sink {
public:
    /**
     * @brief Constructor
     * @param base_filename Base name of the log file
     * @param level Minimum log level this sink will process
     * @param max_size Maximum size of a log file before rotation, in bytes
     * @param max_files Maximum number of rotated log files to keep
     */
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
    
    /**
     * @brief Destructor
     * 
     * Closes the log file.
     */
    ~FileSink() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.close();
        }
    }
    
    /**
     * @brief Process a log record by writing it to a file
     * @param record The log record to process
     */
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
    /**
     * @brief Format a log record for file output
     * @param record The log record to format
     * @return Formatted log message
     */
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
    
    /**
     * @brief Open the log file
     */
    void open_file() {
        file_.open(base_filename_, std::ios::app);
        if (file_.is_open()) {
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
    }
    
    /**
     * @brief Rotate log files
     * 
     * Closes the current log file, shifts existing rotated files,
     * and opens a new log file.
     */
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
    
    std::string base_filename_;  /**< Base name of the log file */
    size_t max_size_;           /**< Maximum size of a log file before rotation */
    int max_files_;             /**< Maximum number of rotated log files to keep */
    size_t current_size_;       /**< Current size of the log file */
    std::ofstream file_;        /**< Output file stream */
    std::mutex mutex_;          /**< Mutex for thread safety */
};

/**
 * @class JsonFileSink
 * @brief File sink that writes log records in JSON format
 */
class JsonFileSink : public Sink {
public:
    /**
     * @brief Constructor
     * @param base_filename Base name of the log file
     * @param level Minimum log level this sink will process
     * @param max_size Maximum size of a log file before rotation, in bytes
     * @param max_files Maximum number of rotated log files to keep
     */
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
    
    /**
     * @brief Destructor
     * 
     * Closes the log file.
     */
    ~JsonFileSink() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.close();
        }
    }
    
    /**
     * @brief Process a log record by writing it to a file in JSON format
     * @param record The log record to process
     */
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
    /**
     * @brief Open the log file
     */
    void open_file() {
        file_.open(base_filename_, std::ios::app);
        if (file_.is_open()) {
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
    }
    
    /**
     * @brief Rotate log files
     * 
     * Closes the current log file, shifts existing rotated files,
     * and opens a new log file.
     */
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
    
    std::string base_filename_;  /**< Base name of the log file */
    size_t max_size_;           /**< Maximum size of a log file before rotation */
    int max_files_;             /**< Maximum number of rotated log files to keep */
    size_t current_size_;       /**< Current size of the log file */
    std::ofstream file_;        /**< Output file stream */
    std::mutex mutex_;          /**< Mutex for thread safety */
};
#endif // XLOG_NO_FILESYSTEM

/**
 * @class CallbackSink
 * @brief Sink that invokes a custom callback function for each log record
 */
class CallbackSink : public Sink {
public:
    /**
     * @typedef Callback
     * @brief Type definition for the callback function
     */
    using Callback = std::function<void(const LogRecord&)>;
    
    /**
     * @brief Constructor
     * @param callback Function to call for each log record
     * @param level Minimum log level this sink will process
     */
    CallbackSink(Callback callback, Level level = Level::DEBUG)
        : Sink(level), callback_(callback) {}
    
    /**
     * @brief Process a log record by calling the callback function
     * @param record The log record to process
     */
    void log(const LogRecord& record) override {
        if (!should_log(record.level)) return;
        callback_(record);
    }
    
private:
    Callback callback_;  /**< Callback function to call for each log record */
};

/**
 * @class Logger
 * @brief Main logging class that distributes log messages to sinks
 * 
 * The Logger class is the primary interface for application code to generate
 * log messages. It manages a collection of sinks and forwards log records to
 * all of them.
 */
class Logger {
public:
    /**
     * @brief Constructor
     * @param name Logger name that will appear in log records
     * @param level Minimum log level this logger will process
     */
    Logger(const std::string& name, Level level = Level::DEBUG)
        : name_(name), level_(level) {}
    
    /**
     * @brief Add a sink to this logger
     * @tparam SinkPtr Type of the sink pointer (usually std::shared_ptr<SinkType>)
     * @param sink Sink to add
     */
    template<typename SinkPtr>
    void add_sink(SinkPtr sink) {
        std::lock_guard<std::mutex> lock(mutex_);
        sinks_.push_back(std::move(sink));
    }
    
    /**
     * @brief Set the minimum log level
     * @param level New minimum log level
     */
    void set_level(Level level) {
        level_ = level;
    }
    
    /**
     * @brief Get the current minimum log level
     * @return Current minimum level
     */
    Level level() const {
        return level_;
    }
    
    /**
     * @brief Log a message with the specified level
     * @param level Severity level of the message
     * @param message Log message content
     */
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
    
    /**
     * @brief Log a debug message
     * @param message Log message content
     */
    void debug(const std::string& message) {
        log(Level::DEBUG, message);
    }
    
    /**
     * @brief Log an info message
     * @param message Log message content
     */
    void info(const std::string& message) {
        log(Level::INFO, message);
    }
    
    /**
     * @brief Log a warning message
     * @param message Log message content
     */
    void warn(const std::string& message) {
        log(Level::WARN, message);
    }
    
    /**
     * @brief Log an error message
     * @param message Log message content
     */
    void error(const std::string& message) {
        log(Level::ERROR, message);
    }
    
    /**
     * @brief Log a fatal error message
     * @param message Log message content
     */
    void fatal(const std::string& message) {
        log(Level::FATAL, message);
    }
    
private:
    std::string name_;                           /**< Logger name */
    Level level_;                                /**< Minimum log level */
    std::vector<std::shared_ptr<Sink>> sinks_;   /**< Collection of sinks */
    std::mutex mutex_;                           /**< Mutex for thread safety */
};

/**
 * @class LoggerRegistry
 * @brief Singleton registry for managing loggers
 * 
 * The LoggerRegistry maintains a collection of named loggers and ensures
 * that the same logger instance is always returned for a given name.
 */
class LoggerRegistry {
public:
    /**
     * @brief Get the singleton instance
     * @return Reference to the singleton instance
     */
    static LoggerRegistry& instance() {
        static LoggerRegistry registry;
        return registry;
    }
    
    /**
     * @brief Get or create a logger with the specified name
     * 
     * If a logger with the given name already exists, it is returned.
     * Otherwise, a new logger is created, stored, and returned.
     * 
     * @param name Name of the logger
     * @return Shared pointer to the logger
     */
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
    
    /**
     * @brief Set the global log level for all loggers
     * @param level New minimum log level for all loggers
     */
    void set_global_level(Level level) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : loggers_) {
            pair.second->set_level(level);
        }
    }
    
private:
    /**
     * @brief Private constructor for singleton pattern
     */
    LoggerRegistry() = default;
    
    std::unordered_map<std::string, std::shared_ptr<Logger>> loggers_;  /**< Map of logger names to logger instances */
    std::mutex mutex_;  /**< Mutex for thread safety */
};

} // namespace xlog

/**
 * @def XLOG_GET_LOGGER
 * @brief Convenience macro to get a logger from the registry
 * @param name Name of the logger to get or create
 * @return Shared pointer to the logger
 */
#define XLOG_GET_LOGGER(name) xlog::LoggerRegistry::instance().get_or_create(name)

/**
 * @def XLOG_DEBUG
 * @brief Log a debug message
 * 
 * This macro checks the log level before formatting the message to avoid
 * unnecessary string operations when the message would be filtered out.
 * 
 * @param logger Logger to use
 * @param message Message to log (can use stream operators)
 */
#define XLOG_DEBUG(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::DEBUG) { \
            std::ostringstream ss; \
            ss << message; \
            logger->debug(ss.str()); \
        } \
    } while(0)

/**
 * @def XLOG_INFO
 * @brief Log an info message
 * 
 * This macro checks the log level before formatting the message to avoid
 * unnecessary string operations when the message would be filtered out.
 * 
 * @param logger Logger to use
 * @param message Message to log (can use stream operators)
 */
#define XLOG_INFO(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::INFO) { \
            std::ostringstream ss; \
            ss << message; \
            logger->info(ss.str()); \
        } \
    } while(0)

/**
 * @def XLOG_WARN
 * @brief Log a warning message
 * 
 * This macro checks the log level before formatting the message to avoid
 * unnecessary string operations when the message would be filtered out.
 * 
 * @param logger Logger to use
 * @param message Message to log (can use stream operators)
 */
#define XLOG_WARN(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::WARN) { \
            std::ostringstream ss; \
            ss << message; \
            logger->warn(ss.str()); \
        } \
    } while(0)

/**
 * @def XLOG_ERROR
 * @brief Log an error message
 * 
 * This macro checks the log level before formatting the message to avoid
 * unnecessary string operations when the message would be filtered out.
 * 
 * @param logger Logger to use
 * @param message Message to log (can use stream operators)
 */
#define XLOG_ERROR(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::ERROR) { \
            std::ostringstream ss; \
            ss << message; \
            logger->error(ss.str()); \
        } \
    } while(0)

/**
 * @def XLOG_FATAL
 * @brief Log a fatal error message
 * 
 * This macro checks the log level before formatting the message to avoid
 * unnecessary string operations when the message would be filtered out.
 * 
 * @param logger Logger to use
 * @param message Message to log (can use stream operators)
 */
#define XLOG_FATAL(logger, message) \
    do { \
        if (logger->level() <= xlog::Level::FATAL) { \
            std::ostringstream ss; \
            ss << message; \
            logger->fatal(ss.str()); \
        } \
    } while(0)

#endif // XLOG_H
