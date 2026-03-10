package oauthErrors

import (
	"errors"
	"fmt"
)

var (
	BadRequestErr = errors.New("Empty access token")
	TokenNotFoundErr = errors.New("Token not found")
	InternalServerErr = errors.New("Internal server error")
)

func NewCustomInternalServerError(message string) error {
	return fmt.Errorf("%w: %s", InternalServerErr, message)
}