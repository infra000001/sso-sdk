package sso

import (
	"fmt"
	"log"
)

// Errors
var (
	ErrUnauthorized  = fmt.Errorf("unauthorized")
	ErrForbidden     = fmt.Errorf("forbidden: insufficient permissions")
	ErrSSOUnreachable = fmt.Errorf("sso server unreachable")
	ErrInvalidConfig = fmt.Errorf("invalid sso configuration")
)

// defaultLogger wraps standard log package.
type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, kvs ...any) { log.Printf("[SSO-DEBUG] "+msg, kvs...) }
func (l *defaultLogger) Info(msg string, kvs ...any)  { log.Printf("[SSO-INFO] "+msg, kvs...) }
func (l *defaultLogger) Warn(msg string, kvs ...any)  { log.Printf("[SSO-WARN] "+msg, kvs...) }
func (l *defaultLogger) Error(msg string, kvs ...any) { log.Printf("[SSO-ERROR] "+msg, kvs...) }
