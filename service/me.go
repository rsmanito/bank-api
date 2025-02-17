package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/storage/postgres"
	"golang.org/x/exp/rand"
)

func parseUserId(ctx context.Context) (uuid.UUID, error) {
	userID, err := uuid.Parse(ctx.Value("userId").(string))
	if err != nil {
		slog.Error("Failed to parse 'sub' as UUID", "err", err, "sub", ctx.Value("userId"))
		return uuid.UUID{}, models.ErrInvalidCreds
	}
	return userID, nil
}

func (s *Service) GetUser(ctx context.Context) (*models.User, error) {
	userID, err := parseUserId(ctx)
	if err != nil {
		return nil, err
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

func (s *Service) GetUserCards(ctx context.Context) ([]*models.Card, error) {
	userID, err := parseUserId(ctx)
	if err != nil {
		return nil, err
	}

	cards, err := s.st.GetUserCards(ctx, pgtype.UUID{
		Bytes: userID,
		Valid: true,
	})
	if err != nil {
		slog.Error("Failed to fetch user cards", "err", err, "userID", userID)
		return nil, errors.New("failed to fetch cards")
	}

	res := make([]*models.Card, 0)
	for i := range cards {
		card := cards[i]
		b, err := card.Balance.Float64Value()
		if err != nil {
			slog.Error("Failed to convert balance to float", "err", err, "userID", userID)
			return nil, errors.New("failed to fetch cards")
		}

		res = append(res, &models.Card{
			Title:    card.Title.String,
			Type:     models.CardType(card.Type),
			Number:   card.Number,
			Balance:  b.Float64,
			Currency: card.Currency,
		})
	}

	return res, nil
}

func (s *Service) CreateCard(ctx context.Context, req *models.CreateCardRequest) (*models.Card, error) {
	userId, err := parseUserId(ctx)
	if err != nil {
		return nil, err
	}

	nCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	number, err := s.generateCardNumber(nCtx)
	if err != nil {
		slog.Error("Failed to generate card number", "err", err)
		return nil, errors.New("failed to create a card")
	}

	params := postgres.CreateCardParams{
		Holder:   pgtype.UUID{Bytes: userId, Valid: true},
		Number:   number,
		Type:     postgres.CardType(req.Type),
		Currency: req.Currency,
	}
	if req.Title != "" {
		params.Title = pgtype.Text{String: req.Title, Valid: true}
	}

	err = s.st.CreateCard(ctx, params)
	if err != nil {
		slog.Error("Failed to save the card", "err", err, "params", params)
		return nil, errors.New("failed to create a card")
	}

	return &models.Card{
		Title:    params.Title.String,
		Type:     models.CardType(params.Type),
		Number:   params.Number,
		Currency: params.Currency,
	}, nil
}

// generateCardNumber returns a unique card number
func (s *Service) generateCardNumber(ctx context.Context) (string, error) {
	charset, length := "1234567890", 16

	for {
		number := func() string {
			n := make([]byte, length)
			for i := range n {
				n[i] = charset[rand.Intn(len(charset))]
			}

			return string(n)
		}()

		exists, err := s.st.CardNumberExists(ctx, number)
		if err != nil {
			slog.Error("Failed to check if card number exists", "err", err)
			return "", err
		}

		if !exists {
			return number, nil
		}
	}
}
