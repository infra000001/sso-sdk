package sso

import "time"

// Version is the SDK version string, sent with sync requests for tracking.
const Version = "0.2.0"

// Config holds SDK configuration. Business applications provide this
// to connect to the SSO server.
type Config struct {
	// ServerURL is the SSO server base URL (e.g., "http://localhost:8080")
	ServerURL string

	// AppKey is the application identifier registered in SSO server
	AppKey string

	// AppSecret is the application secret for SDK authentication
	AppSecret string

	// PublicKeyPath is the local path to RSA public key PEM file.
	// If empty, the SDK fetches it from SSO server on startup.
	PublicKeyPath string

	// CacheTTL is how long to cache permission check results. Default: 5m
	CacheTTL time.Duration

	// SyncOnStartup auto-syncs permissions to SSO server on New(). Default: true
	SyncOnStartup bool

	// SyncRetryCount is the number of retries when Sync() fails. Default: 3
	SyncRetryCount int

	// SyncRetryDelay is the delay between sync retries. Default: 2s
	SyncRetryDelay time.Duration

	// ResyncInterval enables periodic background re-sync. 0 = disabled. Default: 0
	ResyncInterval time.Duration

	// Timeout for SDK HTTP requests. Default: 5s
	Timeout time.Duration

	// FallbackOpen allows requests when SSO server is unreachable.
	// false = fail-closed (deny), true = fail-open (allow). Default: false
	FallbackOpen bool

	// Logger is optional. If nil, uses default std logger.
	Logger Logger
}

// Logger is a simple logging interface.
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(serverURL, appKey, appSecret string) *Config {
	return &Config{
		ServerURL:      serverURL,
		AppKey:         appKey,
		AppSecret:      appSecret,
		CacheTTL:       5 * time.Minute,
		SyncOnStartup:  true,
		SyncRetryCount: 3,
		SyncRetryDelay: 2 * time.Second,
		Timeout:        5 * time.Second,
	}
}
