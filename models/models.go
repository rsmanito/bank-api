package models

import (
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
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Email     string    `json:"email"`
	ID        uuid.UUID `json:"id"`
}

type CardType string

var (
	CardTypeDebit  CardType = "DEBIT"
	CardTypeCredit CardType = "CREDIT"
)

type Card struct {
	Title    string   `json:"title"`
	Type     CardType `json:"type"`
	Number   string   `json:"number"`
	Currency string   `json:"currency"`
	Balance  float64  `json:"balance,string"`
}

type CreateCardRequest struct {
	Title    string `json:"title" validate:"min=4"`
	Currency string `json:"currency" validate:"required,oneof=USD UAH EUR"`
	Type     string `json:"type" validate:"required,oneof=DEBIT CREDIT"`
}
