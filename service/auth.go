package service

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) RegisterUser(req *models.RegisterUserRequest) error {
	uuid4 := uuid.New()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	if err != nil {
		log.Default().Println("Failed to hash password: %w", err)
		return err
	}

	if err := s.st.CreateUser(context.Background(), postgres.CreateUserParams{
		ID:        pgtype.UUID{Bytes: uuid4, Valid: true},
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashedPassword,
	}); err != nil {
		log.Default().Println("Failed to create user: %w", err)
		return err
	}

	return nil
}
