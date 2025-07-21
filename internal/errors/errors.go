package errors

import (
	"fmt"
)

// ErrorType represents the category of error
type ErrorType string

const (
	ConfigError      ErrorType = "CONFIG_ERROR"
	CertError       ErrorType = "CERT_ERROR"
	ValidationError ErrorType = "VALIDATION_ERROR"
	SecurityError   ErrorType = "SECURITY_ERROR"
	IOError         ErrorType = "IO_ERROR"
)

// AppError represents a structured application error
type AppError struct {
	Type    ErrorType              `json:"type"`
	Message string                 `json:"message"`
	Cause   error                  `json:"-"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %s)", e.Type, e.Message, e.Cause.Error())
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

func (e *AppError) WithField(key string, value interface{}) *AppError {
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}
	e.Fields[key] = value
	return e
}

// NewConfigError creates a configuration-related error
func NewConfigError(message string, cause error) *AppError {
	return &AppError{
		Type:    ConfigError,
		Message: message,
		Cause:   cause,
		Fields:  make(map[string]interface{}),
	}
}

// NewCertError creates a certificate-related error
func NewCertError(message string, cause error) *AppError {
	return &AppError{
		Type:    CertError,
		Message: message,
		Cause:   cause,
		Fields:  make(map[string]interface{}),
	}
}

// NewValidationError creates a validation-related error
func NewValidationError(message string, cause error) *AppError {
	return &AppError{
		Type:    ValidationError,
		Message: message,
		Cause:   cause,
		Fields:  make(map[string]interface{}),
	}
}

// NewSecurityError creates a security-related error
func NewSecurityError(message string, cause error) *AppError {
	return &AppError{
		Type:    SecurityError,
		Message: message,
		Cause:   cause,
		Fields:  make(map[string]interface{}),
	}
}

// NewIOError creates an I/O-related error
func NewIOError(message string, cause error) *AppError {
	return &AppError{
		Type:    IOError,
		Message: message,
		Cause:   cause,
		Fields:  make(map[string]interface{}),
	}
}

// IsType checks if the error is of a specific type
func IsType(err error, errorType ErrorType) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
}
