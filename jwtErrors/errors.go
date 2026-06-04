package jwtErrors

import (
	"errors"
	"fmt"
)

var (
	BadRequestErr = errors.New("empty access token")
	UnauthorizedErr   = errors.New("unauthorized")
	InternalServerErr = errors.New("internal server error")
)

func NewCustomInternalServerError(message string) error {
	return fmt.Errorf("%w: %s", InternalServerErr, message)
}