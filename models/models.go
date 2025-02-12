package models

import (
	"time"

	"github.com/google/uuid"
)

type RegisterUserRequest struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
}

type LoginUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type UserLoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	Token        string `json:"token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type User struct {
	CreatedAd time.Time `json:"created_at"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	ID        uuid.UUID `json:"id"`
}
