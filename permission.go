package sso

import "fmt"

// Permission represents an access control entry synced to the SSO server.
type Permission struct {
	Code        string `json:"code"`                  // e.g., "order:create"
	Name        string `json:"name"`                  // Display name, e.g., "Create Order"
	Resource    string `json:"resource,omitempty"`    // Auto-extracted: "order"
	Action      string `json:"action,omitempty"`      // Auto-extracted: "create"
	Path        string `json:"path,omitempty"`        // API path, e.g., "/api/v1/orders"
	Method      string `json:"method,omitempty"`      // HTTP method, e.g., "POST"
	Description string `json:"description,omitempty"` // Optional description
	Group       string `json:"group,omitempty"`       // Group for admin UI organization
	Sort        int    `json:"sort,omitempty"`        // Display order
}

// PermOption configures a Permission.
type PermOption func(*Permission)

// Perm creates a permission marker. Code follows "resource:action" pattern.
//
//	sso.Perm("order:create")
//	sso.Perm("order:create", sso.WithName("Create Order"))
func Perm(code string, opts ...PermOption) *Permission {
	p := &Permission{Code: code}
	p.Resource, p.Action = parseCode(code)
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithName sets the human-readable display name.
func WithName(name string) PermOption { return func(p *Permission) { p.Name = name } }

// WithDescription sets the permission description.
func WithDescription(desc string) PermOption { return func(p *Permission) { p.Description = desc } }

// WithGroup sets the permission group for admin UI.
func WithGroup(group string) PermOption { return func(p *Permission) { p.Group = group } }

// WithSort sets the display sort order.
func WithSort(n int) PermOption { return func(p *Permission) { p.Sort = n } }

// WithPath sets the API path (e.g., "/api/v1/orders").
func WithPath(path string) PermOption { return func(p *Permission) { p.Path = path } }

// WithMethod sets the HTTP method (e.g., "POST").
func WithMethod(method string) PermOption { return func(p *Permission) { p.Method = method } }

// WithRoute is a shortcut for WithPath + WithMethod.
func WithRoute(method, path string) PermOption {
	return func(p *Permission) { p.Method = method; p.Path = path }
}

// parseCode splits "resource:action" into resource and action.
func parseCode(code string) (string, string) {
	for i := range len(code) {
		if code[i] == ':' {
			return code[:i], code[i+1:]
		}
	}
	return code, ""
}

func (p *Permission) String() string {
	if p.Name != "" {
		return fmt.Sprintf("%s (%s)", p.Code, p.Name)
	}
	return p.Code
}
