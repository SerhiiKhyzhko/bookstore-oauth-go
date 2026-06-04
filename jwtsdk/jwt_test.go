package jwtsdk

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SerhiiKhyzhko/bookstore-oauth-go/v2/jwtErrors"
	"github.com/SerhiiKhyzhko/bookstore_utils-go/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	testSecret = "test-secret-key-at-least-32-characters-long"
	testIssuer = "bookstore-oauth-api"
	testUserId = int64(123)
)

// helpers

func setUp() *JwtManager {
	loggerCfg := logger.Config{
		Level:       "info",
		OutputPaths: []string{"stdout"},
	}
	log, _ := logger.NewLogger(loggerCfg)

	return &JwtManager{
		secretKey: testSecret,
		logger:    log,
	}
}

func generateToken(userId int64, tokenType string, exp time.Duration, secret string) string {
	claims := tokenClaims{
		UserId:    userId,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(exp)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString([]byte(secret))
	return ss
}

func validToken() string {
	return generateToken(testUserId, ClaimsAccess, 15*time.Minute, testSecret)
}

func expiredToken() string {
	return generateToken(testUserId, ClaimsAccess, -1*time.Hour, testSecret)
}

// =====================
// IsPublic
// =====================

func TestIsPublic(t *testing.T) {
	manager := setUp()

	t.Run("NilRequest", func(t *testing.T) {
		result, err := manager.IsPublic(nil)
		assert.False(t, result)
		assert.ErrorIs(t, err, jwtErrors.BadRequestErr)
	})

	t.Run("PublicHeader_True", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXPublic, "true")
		result, err := manager.IsPublic(req)
		assert.True(t, result)
		assert.NoError(t, err)
	})

	t.Run("PublicHeader_False", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXPublic, "false")
		result, err := manager.IsPublic(req)
		assert.False(t, result)
		assert.NoError(t, err)
	})

	t.Run("NoHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		result, err := manager.IsPublic(req)
		assert.False(t, result)
		assert.NoError(t, err)
	})
}

// =====================
// AuthenticationRequest
// =====================

func TestAuthenticationRequest(t *testing.T) {
	manager := setUp()

	t.Run("NilRequest", func(t *testing.T) {
		claims, err := manager.AuthenticationRequest(nil)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.BadRequestErr)
	})

	t.Run("MissingAuthHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		claims, err := manager.AuthenticationRequest(req)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.BadRequestErr)
	})

	t.Run("EmptyBearerToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer ")
		claims, err := manager.AuthenticationRequest(req)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.BadRequestErr)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken())

		claims, err := manager.AuthenticationRequest(req)

		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.UnauthorizedErr)
		assert.ErrorContains(t, err, "token expired")
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		token := generateToken(testUserId, ClaimsAccess, 15*time.Minute, "other-secret-key-at-least-32-chars!!")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := manager.AuthenticationRequest(req)

		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.UnauthorizedErr)
		assert.ErrorContains(t, err, "invalid token signature")
	})

	t.Run("MalformedToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer this.is.not.valid")

		claims, err := manager.AuthenticationRequest(req)

		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.UnauthorizedErr)
	})

	t.Run("InvalidTokenType_Refresh", func(t *testing.T) {
		token := generateToken(testUserId, "refresh", 15*time.Minute, testSecret)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := manager.AuthenticationRequest(req)

		assert.Nil(t, claims)
		assert.ErrorIs(t, err, jwtErrors.UnauthorizedErr)
	})

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken())

		claims, err := manager.AuthenticationRequest(req)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, testUserId, claims.UserId)
		assert.Equal(t, ClaimsAccess, claims.TokenType)
		assert.Equal(t, testIssuer, claims.Issuer)
		assert.Greater(t, claims.ExpiresAt, time.Now().Unix())
	})
}
