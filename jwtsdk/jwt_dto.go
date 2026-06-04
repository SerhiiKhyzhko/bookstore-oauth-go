package jwtsdk

import (
	"fmt"

	"github.com/SerhiiKhyzhko/bookstore_utils-go/logger"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ClaimsAccess = "access"
)

type JwtManager struct {
	secretKey string
	logger    *logger.Logger
}

type Claims struct {
	UserId    int64  `json:"user_id"`
	TokenType string `json:"token_type"`
	Issuer    string `json:"issuer"`
	ExpiresAt int64  `json:"expires_at"`
}

type tokenClaims struct {
	UserId    int64  `json:"user_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func (tc *tokenClaims) Validate() error {
	if tc.TokenType != ClaimsAccess {
		return fmt.Errorf("invalid token type: %s", tc.TokenType)
	}

	if tc.UserId <= 0 {
		return fmt.Errorf("invalid user id: %d", tc.UserId)
	}
	return nil
}
