package models

import "time"

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

type User struct {
	CreatedAd     time.Time `json:"created_at"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	UUID          int64     `json:"id"`
	AccountNumber int64     `json:"account_number"`
}

// NewUser returns a new User.
func NewUser(firstName, lastName string) *User {
	return &User{
		UUID:          1,
		FirstName:     firstName,
		LastName:      lastName,
		AccountNumber: 1,
		CreatedAd:     time.Now(),
	}
}
