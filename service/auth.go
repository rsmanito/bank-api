package service

import (
	"context"
	"errors"
	"fmt"
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

	token, refresh, err := s.generateTokens(
		&models.User{
			ID: user.ID.Bytes,
		},
	)
	if err != nil {
		log.Default().Println("Failed to generate tokens: ", err)
		return nil, errors.New("failed to authorize")
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

// RefreshToken handles token refresh logic
func (s *Service) RefreshToken(ctx context.Context, req *models.RefreshTokenRequest) (*models.UserLoginResponse, error) {
	signingKey := []byte(s.cfg.JWT_SIGNING_KEY)

	// Validate Access Token
	_, err := s.validateToken(req.Token, signingKey)
	if err == nil {
		log.Println("Access token is still valid, returning existing tokens")
		return &models.UserLoginResponse{
			Token:        req.Token,
			RefreshToken: req.RefreshToken,
		}, nil
	}

	log.Printf("Access token invalid or expired: %v", err)

	// Validate refresh token
	refreshClaims, err := s.validateToken(req.RefreshToken, signingKey)
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors&jwt.ValidationErrorExpired != 0 {
			log.Println("Refresh token is expired")
			return nil, models.ErrTokensExpired
		}

		log.Printf("Failed to parse refresh token: %v", err)
		return nil, models.ErrInvalidCreds
	}

	// Extract user ID from refresh token
	sub, ok := refreshClaims["sub"].(string)
	if !ok {
		log.Println("Refresh token missing 'sub' field")
		return nil, models.ErrInvalidCreds
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		log.Printf("Failed to parse subject as UUID: %v", err)
		return nil, models.ErrInvalidCreds
	}

	// Generate new tokens
	newToken, newRefresh, err := s.generateTokens(&models.User{ID: userID})
	if err != nil {
		log.Printf("Failed to generate new tokens: %v", err)
		return nil, errors.New("failed to refresh tokens")
	}

	// Store new tokens
	err = s.st.SaveUserTokens(ctx, postgres.SaveUserTokensParams{
		UserID:       pgtype.UUID{Bytes: userID, Valid: true},
		Token:        []byte(newToken),
		RefreshToken: []byte(newRefresh),
	})
	if err != nil {
		log.Printf("Failed to save new tokens: %v", err)
		return nil, errors.New("failed to refresh tokens")
	}

	log.Println("[INFO] Tokens refreshed successfully")
	return &models.UserLoginResponse{
		Token:        newToken,
		RefreshToken: newRefresh,
	}, nil
}

var ErrTokenExpired = errors.New("token expired")

// validateToken extracts claims from a JWT token and verifies its signature
func (s *Service) validateToken(tokenStr string, signingKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	// Extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims format")
	}

	return claims, nil
}

// generateTokens generates access and refresh tokens signed with a key from config.
func (s *Service) generateTokens(u *models.User) (string, string, error) {
	signingKey := []byte(s.cfg.JWT_SIGNING_KEY)

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}).SignedString(signingKey)
	if err != nil {
		log.Default().Println("Failed to create token: ", err)
		return "", "", err
	}

	refresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	}).SignedString(signingKey)
	if err != nil {
		log.Default().Println("Failed to create token: ", err)
		return "", "", err
	}

	return token, refresh, nil
}
