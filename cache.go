package sso

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Cache provides TTL-based caching for permission check results.
// The Cache is safe for concurrent use.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
	stopCh  chan struct{} // signals cleanup goroutine to stop
}

type cacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

// NewCache creates a new cache with the specified TTL.
func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

func cacheKey(userID uint64, perm string) string {
	return fmt.Sprintf("%d:%s", userID, perm)
}

// Get retrieves a cached result. Returns (allowed, found).
func (c *Cache) Get(userID uint64, perm string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cacheKey(userID, perm)]
	if !ok || time.Now().After(e.expiresAt) {
		return false, false
	}
	return e.allowed, true
}

// Set stores a permission check result.
func (c *Cache) Set(userID uint64, perm string, allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(userID, perm)] = cacheEntry{
		allowed:   allowed,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Clear removes all entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// InvalidateByUser removes all entries for a specific user.
func (c *Cache) InvalidateByUser(userID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := fmt.Sprintf("%d:", userID)
	for k := range c.entries {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			delete(c.entries, k)
		}
	}
}

// Stop signals the cleanup goroutine to stop. Safe to call multiple times.
func (c *Cache) Stop() {
	select {
	case <-c.stopCh:
		// already closed
	default:
		close(c.stopCh)
	}
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, e := range c.entries {
				if now.After(e.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// ContextKey is used to store user info in context.
type ContextKey string

const (
	UserIDKey   ContextKey = "sso_user_id"
	TenantIDKey ContextKey = "sso_tenant_id"
	UsernameKey ContextKey = "sso_username"
	RolesKey    ContextKey = "sso_roles"
)

// UserID extracts the user ID from context.
func UserID(ctx context.Context) uint64 {
	v, _ := ctx.Value(UserIDKey).(uint64)
	return v
}

// TenantID extracts the tenant ID from context.
func TenantID(ctx context.Context) uint64 {
	v, _ := ctx.Value(TenantIDKey).(uint64)
	return v
}

// Username extracts the username from context.
func Username(ctx context.Context) string {
	v, _ := ctx.Value(UsernameKey).(string)
	return v
}

// Roles extracts user roles from context.
func Roles(ctx context.Context) []string {
	v, _ := ctx.Value(RolesKey).([]string)
	return v
}

// WithUser stores user info in context.
func WithUser(ctx context.Context, userID, tenantID uint64, username string, roles []string) context.Context {
	ctx = context.WithValue(ctx, UserIDKey, userID)
	ctx = context.WithValue(ctx, TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, UsernameKey, username)
	ctx = context.WithValue(ctx, RolesKey, roles)
	return ctx
}
