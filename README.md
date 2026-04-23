# bookstore-oauth-go
A helper Go library for interacting with an OAuth2 API.

## Purpose
This library is an internal tool designed for authenticating requests between microservices within the "Bookstore" ecosystem. It provides a client to validate an access token via a central OAuth service.

Its main purpose is to abstract the token validation logic and provide a simple interface for securing endpoints.

## Installation

```shell
go get github.com/SerhiiKhyzhko/bookstore-oauth-go
```

## Usage
### 1. Initialize the Client
The client should be initialized once when your application starts, providing the base URL of the OAuth service and a desired request timeout.
```go
import (
    "time"
    "github.com/SerhiiKhyzhko/bookstore-oauth-go/oauth"
)

var (
     // Initialize the client with your OAuth service URL and a 100ms timeout.
    oauthClient = oauth.NewOAuthClient("http://localhost:8080", 100*time.Millisecond)
)
```
### 2. Secure Endpoints (Middleware Example)
The library's main function, AuthenticationRequest, checks for the presence and validity of an access_token in an incoming HTTP request. On success, it enriches the request by adding X-Caller-Id and X-Client-Id headers.

Here is an example of a simple middleware that can be used with any Go web framework (e.g., net/http, Gin, Echo):

```go
import (
    "net/http"
)

func Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Bypass public requests that have the X-Public: true header
        if oauthClient.IsPublic(r) {
            next.ServeHTTP(w, r)
            return
        }

        // Perform request authentication
        if err := oauthClient.AuthenticationRequest(r); err != nil {
            // If the token is invalid or missing, return an error
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // If everything is okay, pass control to the next handler
        next.ServeHTTP(w, r)
    })
}

// Example usage:
// protectedHandler := http.HandlerFunc(myProtectedHandler)
// http.Handle("/resource", Authenticate(protectedHandler))
```
After successful authentication, you can safely retrieve the user and client IDs from the headers within myProtectedHandler:

```go
func myProtectedHandler(w http.ResponseWriter, r *http.Request) {
    callerID, _ := oauthClient.GetCallerId(r)
    clientID, _ := oauthClient.GetClientId(r)

    // ... your logic here ...
}
```

## API Overview

-   `NewOAuthClient(baseUrl string, timeout time.Duration) *OAuthClient`: Creates a new instance of the OAuth client.
-   `AuthenticationRequest(request *http.Request) error`: Validates the access token. Returns nil on success or an error if the token is invalid, missing, or an internal error occurs. **Important:** This function modifies the passed `*http.Request` by adding headers to it.
-   `IsPublic(request *http.Request) bool`:  Checks if a request is public (i.e., if it contains the `X-Public: true` header).
-   `GetCallerId(request *http.Request) (int64, bool)`: A helper function to get the user ID (`caller`)  from the request header after successful authentication.
-   `GetClientId(request *http.Request) (int64, bool)`: A helper function to get the client ID from the request header after successful authentication.