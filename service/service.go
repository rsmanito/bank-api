package service

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/storage"
	"github.com/rsmanito/bank-api/storage/postgres"
)

type Storage interface {
	CreateUser(context.Context, postgres.CreateUserParams) error
	GetUserByEmail(context.Context, string) (postgres.User, error)
	GetUserById(context.Context, pgtype.UUID) (postgres.User, error)
	SaveUserTokens(context.Context, postgres.SaveUserTokensParams) error
	GetUserTokens(context.Context, pgtype.UUID) (postgres.Token, error)
}

type Service struct {
	st  Storage
	cfg *config.Config
}

// New returns a new Service.
func New(st *storage.Storage, cfg *config.Config) *Service {
	return &Service{
		st:  st,
		cfg: cfg,
	}
}
