package sso

import (
	"crypto/rsa"
	"fmt"
	"os"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT token payload from the SSO server.
type Claims struct {
	UserID   uint64   `json:"user_id"`
	TenantID uint64   `json:"tenant_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
	jwtv5.RegisteredClaims
}

// JWTValidator validates RS256 JWT tokens.
type JWTValidator struct {
	publicKey *rsa.PublicKey
}

// NewJWTValidator loads the RSA public key from file.
func NewJWTValidator(publicKeyPath string) (*JWTValidator, error) {
	v := &JWTValidator{}
	if publicKeyPath != "" {
		data, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		key, err := jwtv5.ParseRSAPublicKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		v.publicKey = key
	}
	return v, nil
}

// SetPublicKey sets the RSA public key (used when fetched from SSO server).
func (v *JWTValidator) SetPublicKey(key *rsa.PublicKey) { v.publicKey = key }

// HasKey returns true if the public key is loaded.
func (v *JWTValidator) HasKey() bool { return v.publicKey != nil }

// Validate parses and validates a JWT token string.
func (v *JWTValidator) Validate(tokenStr string) (*Claims, error) {
	if v.publicKey == nil {
		return nil, fmt.Errorf("public key not loaded")
	}
	token, err := jwtv5.ParseWithClaims(tokenStr, &Claims{}, func(t *jwtv5.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv5.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwtv5.ErrTokenInvalidClaims
	}
	return claims, nil
}
