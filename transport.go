package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// sdkEndpoint is the hardcoded SDK API path prefix on the SSO server.
const sdkEndpoint = "/sso-api/v1"

// Transport handles HTTP communication with the SSO server.
type Transport struct {
	baseURL   string
	appKey    string
	appSecret string
	client    *http.Client
}

// NewTransport creates a new transport.
// baseURL is the SSO server address (e.g., "http://localhost:8080").
func NewTransport(baseURL, appKey, appSecret string, timeout time.Duration) *Transport {
	return &Transport{
		baseURL:   baseURL,
		appKey:    appKey,
		appSecret: appSecret,
		client:    &http.Client{Timeout: timeout},
	}
}

// SyncReq is the request body for permission sync.
type SyncReq struct {
	AppKey      string       `json:"app_key"`
	AppSecret   string       `json:"app_secret"`
	Permissions []Permission `json:"permissions"`
	Version     string       `json:"version,omitempty"` // SDK version for tracking
	PermHash    string       `json:"perm_hash,omitempty"` // permission set hash for idempotency
}

// SyncResp is the response from permission sync.
type SyncResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Synced  int      `json:"synced"`
		Created []string `json:"created,omitempty"`
		Updated []string `json:"updated,omitempty"`
	} `json:"data,omitempty"`
}

// EnforceReq is the request body for permission check.
type EnforceReq struct {
	AppKey     string `json:"app_key"`
	AppSecret  string `json:"app_secret"`
	UserID     uint64 `json:"user_id"`
	TenantID   uint64 `json:"tenant_id"`
	Permission string `json:"permission"`
}

// EnforceResp is the response from permission check.
type EnforceResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Allowed bool `json:"allowed"`
	} `json:"data,omitempty"`
}

// PublicKeyResp is the response from public key endpoint.
type PublicKeyResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		PublicKey string `json:"public_key"`
	} `json:"data,omitempty"`
}

// UserInfoReq is the request body for user info query.
type UserInfoReq struct {
	AppKey    string `json:"app_key"`
	AppSecret string `json:"app_secret"`
	UserID    uint64 `json:"user_id"`
	TenantID  uint64 `json:"tenant_id"`
}

// UserInfoResp is the response from user info endpoint.
type UserInfoResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    *UserInfoData `json:"data,omitempty"`
}

// UserInfoData holds real-time user information from the SSO server.
type UserInfoData struct {
	ID       uint64   `json:"id"`
	Username string   `json:"username"`
	Nickname string   `json:"nickname"`
	Email    string   `json:"email"`
	Phone    string   `json:"phone"`
	Avatar   string   `json:"avatar"`
	Status   int8     `json:"status"`  // 0=disabled, 1=active, 2=locked
	Roles    []string `json:"roles"`
}

// Sync sends permissions to the SSO server.
func (t *Transport) Sync(ctx context.Context, perms []Permission, permHash string) (*SyncResp, error) {
	body, err := json.Marshal(SyncReq{
		AppKey:      t.appKey,
		AppSecret:   t.appSecret,
		Permissions: perms,
		Version:     Version,
		PermHash:    permHash,
	})
	if err != nil {
		return nil, err
	}
	var resp SyncResp
	if err := t.post(ctx, "/sdk/sync", body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("sync failed: %s", resp.Message)
	}
	return &resp, nil
}

// Enforce checks if a user has a permission.
func (t *Transport) Enforce(ctx context.Context, userID, tenantID uint64, perm string) (bool, error) {
	body, err := json.Marshal(EnforceReq{
		AppKey: t.appKey, AppSecret: t.appSecret,
		UserID: userID, TenantID: tenantID, Permission: perm,
	})
	if err != nil {
		return false, err
	}
	var resp EnforceResp
	if err := t.post(ctx, "/sdk/enforce", body, &resp); err != nil {
		return false, err
	}
	if resp.Code != 0 {
		return false, fmt.Errorf("enforce failed: %s", resp.Message)
	}
	return resp.Data.Allowed, nil
}

// FetchPublicKey retrieves the RSA public key from the SSO server.
func (t *Transport) FetchPublicKey(ctx context.Context) (string, error) {
	var resp PublicKeyResp
	if err := t.get(ctx, "/sdk/public-key", &resp); err != nil {
		return "", err
	}
	if resp.Code != 0 {
		return "", fmt.Errorf("fetch public key failed: %s", resp.Message)
	}
	return resp.Data.PublicKey, nil
}

// UserInfo retrieves real-time user information from the SSO server.
func (t *Transport) UserInfo(ctx context.Context, userID, tenantID uint64) (*UserInfoData, error) {
	body, err := json.Marshal(UserInfoReq{
		AppKey:    t.appKey,
		AppSecret: t.appSecret,
		UserID:    userID,
		TenantID:  tenantID,
	})
	if err != nil {
		return nil, err
	}
	var resp UserInfoResp
	if err := t.post(ctx, "/sdk/user-info", body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("user info failed: %s", resp.Message)
	}
	return resp.Data, nil
}

func (t *Transport) post(ctx context.Context, path string, body []byte, result any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", t.baseURL+sdkEndpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return t.do(req, result)
}

func (t *Transport) get(ctx context.Context, path string, result any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", t.baseURL+sdkEndpoint+path, nil)
	if err != nil {
		return err
	}
	return t.do(req, result)
}

func (t *Transport) do(req *http.Request, result any) error {
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSOUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain body without exposing server internals in error messages
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(result)
}
