package service

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/models"
)

func (s *Service) GetUser(ctx context.Context) (*models.User, error) {
	userID, err := uuid.Parse(ctx.Value("userId").(string))
	if err != nil {
		slog.Error("Failed to parse 'sub' as UUID", "err", err, "sub", ctx.Value("userId"))
		return nil, models.ErrInvalidCreds
	}

	user, err := s.st.GetUserById(ctx, pgtype.UUID{
		Bytes: userID,
		Valid: true,
	})
	if err != nil {
		slog.Error("Failed to fetch user", "err", err, "userID", userID)
		return nil, errors.New("failed to fetch user")
	}

	return &models.User{
		ID:        user.ID.Bytes,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
	}, nil
}
