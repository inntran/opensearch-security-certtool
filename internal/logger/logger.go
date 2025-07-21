package logger

import (
	"fmt"
	"log"
	"os"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	ERROR LogLevel = iota
	WARN
	INFO
	DEBUG
)

// Logger provides structured logging with security considerations
type Logger struct {
	level     LogLevel
	verbose   bool
	errorLog  *log.Logger
	infoLog   *log.Logger
	debugLog  *log.Logger
}

// New creates a new logger instance
func New(verbose bool) *Logger {
	return &Logger{
		level:    INFO,
		verbose:  verbose,
		errorLog: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		infoLog:  log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime),
		debugLog: log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

// Error logs error messages
func (l *Logger) Error(format string, args ...interface{}) {
	l.errorLog.Printf(format, args...)
}

// Warn logs warning messages
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level >= WARN {
		l.infoLog.Printf("WARN: "+format, args...)
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= INFO {
		l.infoLog.Printf(format, args...)
	}
}

// Debug logs debug messages (only when verbose is enabled)
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose && l.level >= DEBUG {
		l.debugLog.Printf(format, args...)
	}
}

// Verbose logs messages only when verbose mode is enabled
func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		fmt.Printf(format, args...)
	}
}

// Security-aware logging functions that avoid logging sensitive data

// LogCertificateAction logs certificate operations without sensitive data
func (l *Logger) LogCertificateAction(action, name, path string) {
	l.Info("Certificate %s: %s -> %s", action, name, path)
}

// LogPasswordGeneration logs password generation without the actual password
func (l *Logger) LogPasswordGeneration(name string) {
	l.Debug("Generated password for: %s", name)
}

// LogConfigGeneration logs configuration file generation
func (l *Logger) LogConfigGeneration(configType, path string) {
	l.Info("Generated %s configuration: %s", configType, path)
}

// LogValidation logs validation results
func (l *Logger) LogValidation(item string, valid bool) {
	status := "valid"
	if !valid {
		status = "invalid"
	}
	l.Info("Validation result for %s: %s", item, status)
}
