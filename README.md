# bookstore-oauth-go

Go SDK for **local JWT validation** in the Bookstore microservices ecosystem (for example, **items API**, **users API**).

Tokens are issued by the **OAuth API**. This library verifies access tokens **in-process** using a shared secret—no HTTP call to OAuth on each request.

## Why this SDK

| Approach | Pros |
|----------|------|
| HTTP `POST /oauth/verify` on every request | Simple, centralised checks |
| **This SDK (local verify)** | Lower latency, no OAuth bottleneck, fits stateless JWT |

The OAuth API may still expose a **development-only** verify endpoint for Postman and manual testing. Production services should use this SDK only. See your OAuth API README for environment guards.

## Requirements

- Go 1.23+
- The same **HS256 secret** as the OAuth API uses to sign tokens
- JWT payload must match the [token claims contract](#token-claims-contract) below

## Installation

```shell
go get github.com/SerhiiKhyzhko/bookstore-oauth-go/jwtsdk
```

Direct dependency: `github.com/golang-jwt/jwt/v5`.

## Quick start

### 1. Create the manager

```go
import (
    "github.com/SerhiiKhyzhko/bookstore-oauth-go/jwtsdk"
)

var jwtManager = jwtsdk.NewJwtManager(os.Getenv("JWT_SECRET"), logger)
```

Use the same secret as the OAuth API. Load it from env/config in production—never hardcode.

### 2. Middleware (example)

```go
import (
    "errors"
    "net/http"

    "github.com/SerhiiKhyzhko/bookstore-oauth-go/jwtsdk"
    "github.com/SerhiiKhyzhko/bookstore-oauth-go/jwtErrors"
)

func Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        isPublic, err := jwtManager.IsPublic(r)
        if err != nil {
            next.ServeHTTP(w, r)
            return
        }

        claims, err := jwtManager.AuthenticationRequest(r)
        if err != nil {
            switch {
            case errors.Is(err, jwtErrors.BadRequestErr):
                http.Error(w, "Bad Request", http.StatusBadRequest)
            case errors.Is(err, jwtErrors.UnauthorizedErr):
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
            default:
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
            return
        }

        // Pass claims via context, closure, or your framework request bag.
        _ = claims

        next.ServeHTTP(w, r)
    })
}
```

### 3. Use claims in a handler

After successful authentication, `AuthenticationRequest` returns exported `*jwtsdk.Claims`:

```go
func handler(w http.ResponseWriter, r *http.Request, claims *jwtsdk.Claims) {
    userID := claims.UserId
    tokenType := claims.TokenType
    expiresAt := claims.ExpiresAt // Unix seconds
    _ = userID
    _ = tokenType
    _ = expiresAt
}
```

## Token claims contract

Custom claims (must match what the OAuth API puts in the token):

| JSON field | Type | Rules |
|------------|------|--------|
| `user_id` | number | Must be greater than 0 |
| `token_type` | string | Must be `"access"` (`jwtsdk.ClaimsAccess`) |

Standard registered claims (via `jwt.RegisteredClaims`) include `exp` (required), `iss`, etc.

Validation runs automatically during `jwt.ParseWithClaims` via `TokenClaims.Validate()`.

**Important:** If the OAuth API changes claim names or rules, update this SDK (or a shared contract package) in sync.

## API reference

### Package `jwtsdk`

| Symbol | Description |
|--------|-------------|
| `NewJwtManager(secret string) *JwtManager` | Creates a manager with the HS256 signing secret. |
| `(*JwtManager) AuthenticationRequest(r *http.Request) (*Claims, error)` | Reads `Authorization: Bearer <token>`|
| `(*JwtManager) IsPublic(r *http.Request) bool` | `true` when `X-Public: true`. |
| `Claims` | Exported verified claims: `UserId`, `TokenType`, `Issuer`, `ExpiresAt`. |
| `ClaimsAccess` | Constant `"access"` for allowed `token_type`. |

### Package `jwtErrors`

Sentinel errors for `errors.Is` when mapping to your HTTP layer (for example, Gin + `rest_errors`):

| Error | When |
|-------|------|
| `BadRequestErr` | Missing/empty Bearer token |
| `UnauthorizedErr` | Invalid, expired, or malformed token; failed claim validation |
| `InternalServerErr` | Unexpected verification failure (via `NewCustomInternalServerError`) |

## Security notes

- Only **HS256** is accepted (`jwt.WithValidMethods`, `jwt.WithExpirationRequired`).
- Invalid tokens map to `UnauthorizedErr` (treat as 401 in your API).
- Rotate secrets via env/config; keep OAuth API and all consumers on the same secret.

## Project layout

```
jwtsdk/
  manager.go   # NewJwtManager
  jwt_dto.go   # JwtManager, Claims, TokenClaims, Validate
  jwt.go       # AuthenticationRequest, verifyToken
jwtErrors/
  errors.go    # Sentinel errors
```

## Development

```shell
go build ./jwtsdk/...
go test ./jwtsdk/...   # after tests are updated for local JWT
```

## Related services

- **OAuth API** — issues tokens; may expose dev-only verify for debugging.
- **items / users API** — should depend on `jwtsdk` for authentication in production.
