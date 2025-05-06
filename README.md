# XLog

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C++-17-green.svg)](https://en.cppreference.com/w/cpp/17)

A lightweight, header-only, cross-platform C++ logging library suitable for both desktop and embedded systems.

## Features

- **Multiple Log Levels** - DEBUG, INFO, WARN, ERROR, FATAL
- **Multiple Output Destinations**
  - Console logging (stdout/stderr)
  - File logging with rotation
  - JSON formatting
  - Syslog integration (local and remote via UDP)
  - Custom callback sinks
- **Cross-Platform Compatibility**
  - Works on Windows, Linux, macOS
  - Special embedded mode for resource-constrained systems
- **Thread Safety** - Safe to use from multiple threads
- **Header-Only** - Just include and go
- **No External Dependencies** - Self-contained for easy integration
- **Configurable** - Multiple loggers, log levels, and formatter options

## Installation

Since XLog is a header-only library, you can simply copy `xlog.h` to your project or add this repository as a submodule:

```bash
# Add as a submodule
git submodule add https://github.com/DatanoiseTV/xlog.git

# Or just download the header
wget https://raw.githubusercontent.com/DatanoiseTV/xlog/main/xlog.h
```

Then include it in your project:

```cpp
#include "xlog.h"
```

## Basic Usage

```cpp
#include "xlog.h"

int main() {
    // Create a logger
    auto logger = XLOG_GET_LOGGER("MyApp");
    
    // Add console sink (stdout)
    auto console_sink = std::make_shared<xlog::ConsoleSink>();
    logger->add_sink(console_sink);
    
    // Log at different levels
    XLOG_DEBUG(logger, "Debug message");
    XLOG_INFO(logger, "Info message with value: " << 42);
    XLOG_WARN(logger, "Warning message");
    XLOG_ERROR(logger, "Error message");
    XLOG_FATAL(logger, "Fatal error message");
    
    return 0;
}
```

## Compilation

To compile with G++:

```bash
g++ -std=c++17 your_program.cpp -o your_program
```

For older versions of G++ (before 9.1), you may need to link against the filesystem library:

```bash
g++ -std=c++17 your_program.cpp -o your_program -lstdc++fs
```

## Advanced Usage

### File Logging with Rotation

```cpp
// Add file sink with rotation
auto file_sink = std::make_shared<xlog::FileSink>(
    "app.log",         // Base filename
    xlog::Level::INFO, // Min level
    1024 * 1024,       // Max size (1MB)
    3                  // Max files
);
logger->add_sink(file_sink);
```

When the log file reaches the maximum size, it will be renamed to `app.log.1`, and a new `app.log` will be created. Up to the specified number of backup files will be kept.

### JSON Logging

XLog supports outputting logs in JSON format for machine parsing:

```cpp
// Add JSON console sink
auto json_console_sink = std::make_shared<xlog::JsonConsoleSink>();
logger->add_sink(json_console_sink);

// Add JSON file sink
auto json_file_sink = std::make_shared<xlog::JsonFileSink>("app.json.log");
logger->add_sink(json_file_sink);

// Example output:
// {"timestamp":"2025-05-06T10:15:32","level":"INFO","logger":"MyApp","message":"Example message"}
```

### Syslog Integration

XLog supports both local and remote syslog for UNIX-based systems:

```cpp
// Local syslog
#ifdef XLOG_SYSLOG_AVAILABLE
    auto syslog_sink = std::make_shared<xlog::SyslogSink>(
        "myapp",         // Application identifier
        xlog::Level::INFO,  // Min level
        LOG_USER        // Facility
    );
    logger->add_sink(syslog_sink);
    
    // Remote syslog
    auto remote_syslog_sink = std::make_shared<xlog::RemoteSyslogSink>(
        "log-server.example.com",  // Remote server hostname or IP
        514,                      // Standard syslog port
        "myapp",                  // Application name
        xlog::Level::WARN         // Min level
    );
    logger->add_sink(remote_syslog_sink);
#endif
```

The remote syslog sink implements the RFC 5424 protocol over UDP, making it compatible with most syslog servers like rsyslog, syslog-ng, or cloud-based log management systems.

### Custom Callback Sink

You can create custom sinks using the callback functionality:

```cpp
// Custom sink for network logging
auto network_sink = std::make_shared<xlog::CallbackSink>(
    [](const xlog::LogRecord& record) {
        // Send log over network, store in database, etc.
        std::string json = xlog::JsonFormatter::format(record);
        // NetworkService::send(json);
    },
    xlog::Level::WARN  // Only send warnings and above
);
logger->add_sink(network_sink);
```

### Multiple Loggers

Create separate loggers for different components:

```cpp
auto app_logger = XLOG_GET_LOGGER("App");
auto db_logger = XLOG_GET_LOGGER("Database");
auto net_logger = XLOG_GET_LOGGER("Network");

// Add sinks to each logger
app_logger->add_sink(console_sink);
db_logger->add_sink(console_sink);
db_logger->add_sink(file_sink);
net_logger->add_sink(console_sink);

// Log with the appropriate logger
XLOG_INFO(app_logger, "Application started");
XLOG_INFO(db_logger, "Database connection established");
XLOG_INFO(net_logger, "Listening on port 8080");
```

### Embedded Systems

XLog includes a special mode for embedded systems with reduced feature set:

```cpp
// Define XLOG_EMBEDDED before including xlog.h
#define XLOG_EMBEDDED
#include "xlog.h"

// Create a logger with minimal configuration
auto logger = XLOG_GET_LOGGER("EmbeddedApp");

// Add console sink
auto console_sink = std::make_shared<xlog::ConsoleSink>();
logger->add_sink(console_sink);

// Add custom callback sink for serial output
auto serial_sink = std::make_shared<xlog::CallbackSink>(
    [](const xlog::LogRecord& record) {
        // Write to serial port
        // SerialPort::write(level_to_string(record.level) + ": " + record.message);
    }
);
logger->add_sink(serial_sink);
```

## Performance Considerations

- Log level checks are performed before string formatting to avoid unnecessary processing.
- Thread safety is implemented with minimal locking.
- The embedded mode reduces memory and CPU usage for resource-constrained systems.
- Macros allow the compiler to optimize out disabled log levels.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements

- Asynchronous logging
- Pattern-based filtering
- Memory circular buffer sink
- Structured logging
- More network protocols
- Log batching
- Configuration from file
- Contextual logging

## License

This project is licensed under the MIT License - see the LICENSE file for details.
