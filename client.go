package sso

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Client is the main SSO SDK client. Business applications create one
// Client instance and use it to declare, sync, and enforce permissions.
//
// The Client is safe for concurrent use.
//
// Usage:
//
//	client, _ := sso.New(&sso.Config{
//	    ServerURL: "http://localhost:8080",
//	    AppKey:    "my-app",
//	    AppSecret: "your-app-secret-here",
//	})
//	defer client.Close()
//	client.Sync(ctx) // sync permissions on startup
type Client struct {
	cfg       *Config
	jwt       *JWTValidator
	transport *Transport
	cache     *Cache
	log       Logger

	mu          sync.RWMutex
	permMap     map[string]*Permission // code → permission (idempotent)
	permVersion string                 // hash of current permission set
	synced      atomic.Bool            // true after first successful sync

	done     chan struct{}  // signals all goroutines to stop
	closeOnce sync.Once     // ensures Close() runs exactly once
}

// New creates a new SSO client.
func New(cfg *Config) (*Client, error) {
	if cfg == nil || cfg.ServerURL == "" || cfg.AppKey == "" || cfg.AppSecret == "" {
		return nil, ErrInvalidConfig
	}

	// Apply defaults
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.SyncRetryCount == 0 {
		cfg.SyncRetryCount = 3
	}
	if cfg.SyncRetryDelay == 0 {
		cfg.SyncRetryDelay = 2 * time.Second
	}

	log := cfg.Logger
	if log == nil {
		log = &defaultLogger{}
	}

	// Warn when not using HTTPS — AppSecret is transmitted in plaintext over HTTP
	if len(cfg.ServerURL) > 7 && cfg.ServerURL[:7] == "http://" {
		log.Warn("ServerURL uses HTTP, consider switching to HTTPS to protect AppSecret in transit")
	}

	jwt, err := NewJWTValidator(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("init jwt: %w", err)
	}

	transport := NewTransport(cfg.ServerURL, cfg.AppKey, cfg.AppSecret, cfg.Timeout)
	cache := NewCache(cfg.CacheTTL)

	c := &Client{
		cfg:       cfg,
		jwt:       jwt,
		transport: transport,
		cache:     cache,
		log:       log,
		permMap:   make(map[string]*Permission),
		done:      make(chan struct{}),
	}

	// If no local public key, fetch from SSO server (with goroutine safety)
	if !jwt.HasKey() {
		go c.safeGo("fetchPublicKey", c.fetchPublicKey)
	}

	return c, nil
}

// Register adds permissions to the client's registry.
// Duplicate codes are silently ignored (idempotent).
// These will be synced to the SSO server on Sync().
func (c *Client) Register(perms ...*Permission) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range perms {
		if p == nil || p.Code == "" {
			continue
		}
		if _, exists := c.permMap[p.Code]; exists {
			c.log.Debug("Permission already registered, skipping", "code", p.Code)
			continue
		}
		c.permMap[p.Code] = p
	}
}

// Sync sends all registered permissions to the SSO server with retry.
// Returns nil on success, ErrSyncFailed after all retries are exhausted.
func (c *Client) Sync(ctx context.Context) error {
	c.mu.RLock()
	perms := make([]Permission, 0, len(c.permMap))
	for _, p := range c.permMap {
		perms = append(perms, *p)
	}
	c.mu.RUnlock()

	if len(perms) == 0 {
		c.log.Info("No permissions to sync")
		c.synced.Store(true)
		return nil
	}

	// P2: Validate permissions before sync
	if errs := validatePermissions(perms); len(errs) > 0 {
		for _, e := range errs {
			c.log.Warn("Permission validation warning", "err", e)
		}
	}

	// Compute version for tracking
	version := computeVersion(perms)

	c.log.Info("Syncing permissions", "count", len(perms), "version", version[:8])

	// Retry with backoff
	var lastErr error
	for attempt := 0; attempt <= c.cfg.SyncRetryCount; attempt++ {
		if attempt > 0 {
			delay := c.cfg.SyncRetryDelay * time.Duration(attempt)
			c.log.Info("Retrying sync", "attempt", attempt, "delay", delay.String())
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: context cancelled", ErrSyncFailed)
			case <-time.After(delay):
			}
		}

		resp, err := c.transport.Sync(ctx, perms, version)
		if err != nil {
			lastErr = err
			c.log.Warn("Sync attempt failed", "attempt", attempt+1, "err", err)
			continue
		}

		c.log.Info("Permissions synced",
			"synced", resp.Data.Synced,
			"created", len(resp.Data.Created),
			"updated", len(resp.Data.Updated),
		)
		c.synced.Store(true)
		c.mu.Lock()
		c.permVersion = version
		c.mu.Unlock()
		return nil
	}

	return fmt.Errorf("%w (after %d attempts): %v", ErrSyncFailed, c.cfg.SyncRetryCount+1, lastErr)
}

// Synced returns true if at least one successful sync has completed.
func (c *Client) Synced() bool { return c.synced.Load() }

// Enforce checks if a user has a specific permission.
func (c *Client) Enforce(ctx context.Context, userID, tenantID uint64, perm string) (bool, error) {
	// Check cache
	if allowed, ok := c.cache.Get(userID, perm); ok {
		return allowed, nil
	}

	// Query SSO server
	allowed, err := c.transport.Enforce(ctx, userID, tenantID, perm)
	if err != nil {
		if c.cfg.FallbackOpen {
			c.log.Warn("SSO unreachable, fallback open", "perm", perm, "err", err)
			return true, nil
		}
		return false, err
	}

	c.cache.Set(userID, perm, allowed)
	return allowed, nil
}

// UserInfo retrieves real-time user information from the SSO server.
// Use this to check user status, roles, etc. beyond what's in the JWT.
func (c *Client) UserInfo(ctx context.Context, userID, tenantID uint64) (*UserInfoData, error) {
	return c.transport.UserInfo(ctx, userID, tenantID)
}

// ValidateToken validates a JWT token and returns claims.
func (c *Client) ValidateToken(tokenStr string) (*Claims, error) {
	return c.jwt.Validate(tokenStr)
}

// ClearCache clears the permission cache.
func (c *Client) ClearCache() { c.cache.Clear() }

// Close cleans up resources and stops all background goroutines.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.cache.Stop()
		c.cache.Clear()
	})
	return nil
}

// StartAutoSync starts a background goroutine that periodically re-syncs permissions.
// Only starts if ResyncInterval > 0. The goroutine is stopped by Close().
func (c *Client) StartAutoSync() {
	if c.cfg.ResyncInterval <= 0 {
		return
	}
	go c.safeGo("autoSync", func() {
		ticker := time.NewTicker(c.cfg.ResyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout*2)
				if err := c.Sync(ctx); err != nil {
					c.log.Error("Auto-sync failed", "err", err)
				}
				cancel()
			}
		}
	})
}

// --- Internal ---

func (c *Client) fetchPublicKey() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Retry fetching public key in background
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-c.done:
			return
		default:
		}

		pemStr, err := c.transport.FetchPublicKey(ctx)
		if err != nil {
			c.log.Warn("Failed to fetch public key", "attempt", attempt+1, "err", err)
			select {
			case <-c.done:
				return
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
			continue
		}

		key, err := jwtv5.ParseRSAPublicKeyFromPEM([]byte(pemStr))
		if err != nil {
			c.log.Warn("Failed to parse public key", "err", err)
			return
		}

		c.jwt.SetPublicKey(key)
		c.log.Info("Public key loaded from SSO server")
		return
	}
}

// safeGo runs fn in a goroutine with panic recovery.
func (c *Client) safeGo(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("Goroutine panic recovered",
				"name", name,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()),
			)
		}
	}()
	fn()
}

// validatePermissions checks for common permission definition errors.
func validatePermissions(perms []Permission) []error {
	var errs []error
	codes := make(map[string]bool, len(perms))

	for _, p := range perms {
		if p.Code == "" {
			errs = append(errs, fmt.Errorf("permission has empty code"))
			continue
		}
		if codes[p.Code] {
			errs = append(errs, fmt.Errorf("duplicate permission code: %s", p.Code))
		}
		codes[p.Code] = true

		// Warn if Method is set but Path is empty (or vice versa)
		if p.Method != "" && p.Path == "" {
			errs = append(errs, fmt.Errorf("permission %q has method but no path", p.Code))
		}
		if p.Path != "" && p.Method == "" {
			errs = append(errs, fmt.Errorf("permission %q has path but no method", p.Code))
		}
	}
	return errs
}

// computeVersion generates a short hash of the permission set for change tracking.
func computeVersion(perms []Permission) string {
	codes := make([]string, len(perms))
	for i, p := range perms {
		codes[i] = p.Code
	}
	slices.Sort(codes)

	// Simple FNV-1a hash → hex string
	var h uint64 = 14695981039346656037
	for _, code := range codes {
		for _, b := range []byte(code) {
			h ^= uint64(b)
			h *= 1099511628211
		}
	}
	return fmt.Sprintf("%016x", h)
}

var ErrSyncFailed = fmt.Errorf("permission sync failed")
