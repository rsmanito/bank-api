package service

import (
	"context"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) RegisterUser(ctx context.Context, req *models.RegisterUserRequest) error {
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

func (s *Service) LoginUser(ctx context.Context, req *models.LoginUserRequest) (res *models.UserLoginResponse, err error) {
	user, err := s.st.GetUserByEmail(ctx, req.Email)
	if err != nil {
		log.Default().Println("Failed to get user: ", err)
		return res, err
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		return res, models.ErrInvalidCreds
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}).SignedString([]byte("supersecret"))
	if err != nil {
		log.Default().Println("Failed to create token: ", err)
		return res, err
	}

	refresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	}).SignedString([]byte("supersecret"))
	if err != nil {
		log.Default().Println("Failed to create token: ", err)
		return res, err
	}

	err = s.st.SaveUserTokens(ctx, postgres.SaveUserTokensParams{
		UserID:       pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		Token:        []byte(token),
		RefreshToken: []byte(refresh),
	})
	if err != nil {
		log.Default().Println("Failed to save token: ", err)
		return res, err
	}

	res = &models.UserLoginResponse{
		Token:        token,
		RefreshToken: refresh,
	}

	return res, nil
}
