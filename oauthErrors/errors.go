package oauthErrors

import (
	"errors"
	"fmt"
)

var (
	BadRequestErr = errors.New("empty access token")
	TokenNotFoundErr = errors.New("token not found")
	InternalServerErr = errors.New("internal server error")
)

func NewCustomInternalServerError(message string) error {
	return fmt.Errorf("%w: %s", InternalServerErr, message)
}