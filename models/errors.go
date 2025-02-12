package models

import "errors"

var (
	ErrInvalidCreds  = errors.New("invalid credentials")
	ErrTokensExpired = errors.New("tokens expired")
)
