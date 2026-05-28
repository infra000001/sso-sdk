# SSO SDK

Go SDK for SSO single sign-on system. Provides authentication, permission checking, and token validation for business applications.

## Installation

```bash
go get github.com/infra000001/sso-sdk
```

## Quick Start

```go
import sso "github.com/infra000001/sso-sdk"

client, err := sso.New(&sso.Config{
    ServerURL: os.Getenv("SSO_SERVER_URL"),
    AppKey:    os.Getenv("SSO_APP_KEY"),
    AppSecret: os.Getenv("SSO_APP_SECRET"),
})
defer client.Close()

// Register permissions
client.Register(
    sso.Perm("order:create", sso.WithName("创建订单"), sso.WithRoute("POST", "/api/v1/orders")),
)

// Sync permissions to SSO server
client.Sync(ctx)

// Enforce permission check
allowed, err := client.Enforce(ctx, userID, tenantID, "order:create")
```

## Gin Middleware

```bash
go get github.com/infra000001/sso-sdk/ginsso
```

```go
import "github.com/infra000001/sso-sdk/ginsso"

mw := ginsso.New(client)
r := gin.Default()
r.Use(mw.Auth())
r.POST("/orders", mw.Require("order:create"), handler)
```
