package service

import (
	"context"

	"github.com/rsmanito/bank-api/storage"
	"github.com/rsmanito/bank-api/storage/postgres"
)

type Storage interface {
	CreateUser(context.Context, postgres.CreateUserParams) error
	GetUserByEmail(context.Context, string) (postgres.User, error)
	SaveUserTokens(context.Context, postgres.SaveUserTokensParams) error
}

type Service struct {
	st Storage
}

// New returns a new Service.
func New(st *storage.Storage) *Service {
	return &Service{
		st: st,
	}
}
