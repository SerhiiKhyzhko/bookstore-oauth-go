package jwtsdk

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/SerhiiKhyzhko/bookstore-oauth-go/v2/jwtErrors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	headerXPublic = "X-Public"
	ClaimsKey     = "claims"
	IsPublicKey   = "isPublic"
)

func (j *JwtManager) IsPublic(request *http.Request) (bool, error) {
	if request == nil {
		return false, jwtErrors.BadRequestErr
	}
	return request.Header.Get(headerXPublic) == "true", nil
}

func (j *JwtManager) AuthenticationRequest(request *http.Request) (*Claims, error) {
	if request == nil {
		return nil, jwtErrors.BadRequestErr
	}

	authHeader := request.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w, empty token", jwtErrors.BadRequestErr)
	}
	jwtClaims, err := j.verifyToken(token)
	if err != nil {
		if errors.Is(err, jwtErrors.UnauthorizedErr) {
			return nil, err
		}
		return nil, jwtErrors.NewCustomInternalServerError(err.Error())
	}

	return &Claims{
		UserId:    jwtClaims.UserId,
		TokenType: jwtClaims.TokenType,
		Issuer:    jwtClaims.Issuer,
		ExpiresAt: jwtClaims.ExpiresAt.Unix(),
	}, nil
}

func (j *JwtManager) verifyToken(tokenString string) (*tokenClaims, error) {
	claims := tokenClaims{}

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		return []byte(j.secretKey), nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		j.logger.Error(err.Error(), err)
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("%w: token expired", jwtErrors.UnauthorizedErr)
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("%w: token not valid yet", jwtErrors.UnauthorizedErr)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, fmt.Errorf("%w: invalid token signature", jwtErrors.UnauthorizedErr)
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("%w: malformed token", jwtErrors.UnauthorizedErr)
		default:
			return nil, fmt.Errorf("%w: invalid token", jwtErrors.UnauthorizedErr)
		}
	}

	if !token.Valid {
		return nil, fmt.Errorf("%w: invalid token", jwtErrors.UnauthorizedErr)
	}

	return &claims, nil
}
