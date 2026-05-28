// Package ginsso provides Gin framework integration for the SSO SDK.
//
// It offers JWT authentication middleware, permission enforcement middleware,
// and automatic route scanning for permission registration.
//
// Usage:
//
//	client, _ := sso.New(&sso.Config{...})
//	defer client.Close()
//
//	r := gin.Default()
//	ssoMW := ginsso.New(client)
//
//	// Protect all routes below with JWT auth
//	api := r.Group("/api/v1")
//	api.Use(ssoMW.Auth())
//
//	// Require specific permissions
//	api.POST("/orders", ssoMW.Require("order:create"), handler.CreateOrder)
//	api.GET("/orders", ssoMW.Require("order:list"), handler.ListOrders)
//
//	// Scan routes and sync permissions on startup
//	perms := []*sso.Permission{
//	    sso.Perm("order:create", sso.WithName("Create Order"), sso.WithRoute("POST", "/api/v1/orders")),
//	    sso.Perm("order:list", sso.WithName("List Orders"), sso.WithRoute("GET", "/api/v1/orders")),
//	}
//	client.Register(perms...)
//	client.Sync(context.Background())
package ginsso

import (
	"net/http"
	"strings"

	sso "github.com/your-org/sso-sdk"

	"github.com/gin-gonic/gin"
)

// Middleware holds the SSO client reference and provides Gin middleware.
type Middleware struct {
	client *sso.Client
}

// New creates a new ginsso middleware instance.
func New(client *sso.Client) *Middleware {
	return &Middleware{client: client}
}

// Auth returns a Gin middleware that validates JWT Bearer tokens.
// On success, it injects user info (user_id, tenant_id, username, roles)
// into the Gin context, accessible via ginsso.UserID(c), etc.
func (m *Middleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearerToken(c.GetHeader("Authorization"))
		if tokenStr == "" {
			abortJSON(c, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}

		claims, err := m.client.ValidateToken(tokenStr)
		if err != nil {
			abortJSON(c, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Store in Gin context for easy access
		c.Set("sso_user_id", claims.UserID)
		c.Set("sso_tenant_id", claims.TenantID)
		c.Set("sso_username", claims.Username)
		c.Set("sso_roles", claims.Roles)

		c.Next()
	}
}

// Require returns a Gin middleware that enforces a specific permission.
// Must be used AFTER Auth() middleware.
//
//	r.POST("/orders", ssoMW.Auth(), ssoMW.Require("order:create"), handler)
func (m *Middleware) Require(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("sso_user_id")
		tenantID, _ := c.Get("sso_tenant_id")

		uid, ok1 := userID.(uint64)
		tid, _ := tenantID.(uint64)
		if !ok1 {
			abortJSON(c, http.StatusUnauthorized, "user context missing, is Auth() middleware applied?")
			return
		}

		allowed, err := m.client.Enforce(c.Request.Context(), uid, tid, perm)
		if err != nil {
			abortJSON(c, http.StatusBadGateway, "permission check failed")
			return
		}
		if !allowed {
			abortJSON(c, http.StatusForbidden, "insufficient permissions: "+perm)
			return
		}

		c.Next()
	}
}

// RequireAny returns middleware that passes if the user has ANY of the listed permissions.
func (m *Middleware) RequireAny(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("sso_user_id")
		tenantID, _ := c.Get("sso_tenant_id")

		uid, ok1 := userID.(uint64)
		tid, _ := tenantID.(uint64)
		if !ok1 {
			abortJSON(c, http.StatusUnauthorized, "user context missing")
			return
		}

		for _, perm := range perms {
			allowed, err := m.client.Enforce(c.Request.Context(), uid, tid, perm)
			if err == nil && allowed {
				c.Next()
				return
			}
		}

		abortJSON(c, http.StatusForbidden, "insufficient permissions")
	}
}

// RequireAll returns middleware that passes only if the user has ALL listed permissions.
func (m *Middleware) RequireAll(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("sso_user_id")
		tenantID, _ := c.Get("sso_tenant_id")

		uid, ok1 := userID.(uint64)
		tid, _ := tenantID.(uint64)
		if !ok1 {
			abortJSON(c, http.StatusUnauthorized, "user context missing")
			return
		}

		for _, perm := range perms {
			allowed, err := m.client.Enforce(c.Request.Context(), uid, tid, perm)
			if err != nil {
				abortJSON(c, http.StatusBadGateway, "permission check failed")
				return
			}
			if !allowed {
				abortJSON(c, http.StatusForbidden, "insufficient permissions: "+perm)
				return
			}
		}

		c.Next()
	}
}

// ScanRoutes scans Gin engine routes and returns matching permissions.
// This helps auto-discover Path/Method for permissions that didn't set them.
//
// Usage:
//
//	perms := []*sso.Permission{
//	    sso.Perm("order:create", sso.WithName("Create Order")),
//	}
//	ginsso.ScanRoutes(engine, perms)
//	client.Register(perms...)
func ScanRoutes(engine *gin.Engine, perms []*sso.Permission) {
	routes := engine.Routes()
	for _, p := range perms {
		if p.Path != "" {
			continue // already has path
		}
		for _, r := range routes {
			if matchPermToRoute(p, r) {
				p.Path = r.Path
				p.Method = r.Method
				break
			}
		}
	}
}

// matchPermToRoute tries to match a permission code to a Gin route.
// Convention: "order:create" → POST /api/v1/orders, "order:list" → GET /api/v1/orders
func matchPermToRoute(p *sso.Permission, r gin.RouteInfo) bool {
	// Simple heuristic: resource name appears in path
	if p.Resource == "" {
		return false
	}
	resource := strings.ToLower(p.Resource)
	path := strings.ToLower(r.Path)
	if !strings.Contains(path, resource) {
		return false
	}

	// Match action to HTTP method
	switch strings.ToLower(p.Action) {
	case "create", "add", "new":
		return r.Method == "POST"
	case "list", "index":
		return r.Method == "GET" && !strings.Contains(path, ":")
	case "get", "show", "view", "detail":
		return r.Method == "GET" && strings.Contains(path, ":")
	case "update", "edit", "modify":
		return r.Method == "PUT" || r.Method == "PATCH"
	case "delete", "remove":
		return r.Method == "DELETE"
	}
	return false
}

// --- Context helpers ---

// UserID extracts user ID from Gin context.
func UserID(c *gin.Context) uint64 {
	v, _ := c.Get("sso_user_id")
	id, _ := v.(uint64)
	return id
}

// TenantID extracts tenant ID from Gin context.
func TenantID(c *gin.Context) uint64 {
	v, _ := c.Get("sso_tenant_id")
	id, _ := v.(uint64)
	return id
}

// Username extracts username from Gin context.
func Username(c *gin.Context) string {
	v, _ := c.Get("sso_username")
	s, _ := v.(string)
	return s
}

// Roles extracts user roles from Gin context.
func Roles(c *gin.Context) []string {
	v, _ := c.Get("sso_roles")
	r, _ := v.([]string)
	return r
}

// --- Internal helpers ---

func extractBearerToken(auth string) string {
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):]
	}
	return ""
}

func abortJSON(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{
		"code":    code,
		"message": msg,
	})
}
