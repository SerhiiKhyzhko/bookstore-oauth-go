package oauthErrors

import (
	"errors"
	"fmt"
)

var (
	BadRequestErr = errors.New("Empty access token")
	NotFoundUserIdErr = errors.New("No user found with such id")
	InternalServerErr = errors.New("Internal server error")
)

func NewCustomInternalServerError(message string) error {
	return fmt.Errorf("%w: %s", InternalServerErr, message)
}