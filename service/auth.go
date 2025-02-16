package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) RegisterUser(ctx context.Context, req *models.RegisterUserRequest) error {
	uuid4 := uuid.New()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	if err != nil {
		slog.Error("Failed to hash password", "err", err)
		return err
	}

	if err := s.st.CreateUser(context.Background(), postgres.CreateUserParams{
		ID:        pgtype.UUID{Bytes: uuid4, Valid: true},
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  hashedPassword,
	}); err != nil {
		slog.Error("Failed to create user", "err", err)
		return err
	}

	return nil
}

func (s *Service) LoginUser(ctx context.Context, req *models.LoginUserRequest) (res *models.UserLoginResponse, err error) {
	user, err := s.st.GetUserByEmail(ctx, req.Email)
	if err != nil {
		slog.Error("Failed to get user", "err", err, "email", req.Email)
		return res, err
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		slog.Debug("Passwords do not match", "userID", user.ID)
		return res, models.ErrInvalidCreds
	}

	token, refresh, err := s.generateTokens(
		&models.User{
			ID: user.ID.Bytes,
		},
	)
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err)
		return nil, errors.New("failed to authorize")
	}

	err = s.st.SaveUserTokens(ctx, postgres.SaveUserTokensParams{
		UserID:       pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		Token:        []byte(token),
		RefreshToken: []byte(refresh),
	})
	if err != nil {
		slog.Error("Failed to save tokens", "err", err, "userID", user.ID)
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
	claims, err := s.validateToken(req.Token, signingKey)
	if err == nil {
		slog.Debug("Access token is still valid, returning existing tokens", "userID", claims["sub"])
		return &models.UserLoginResponse{
			Token:        req.Token,
			RefreshToken: req.RefreshToken,
		}, nil
	}

	slog.Debug("Access token is invalid or expired", "err", err, "userID", claims["sub"])

	// Validate refresh token
	refreshClaims, err := s.validateToken(req.RefreshToken, signingKey)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			slog.Debug("Refresh token is expired", "userID", refreshClaims["sub"])
			return nil, models.ErrTokensExpired
		}

		slog.Error("Failed to parse refresh token", "err", err, "userID", refreshClaims["sub"])
		return nil, models.ErrInvalidCreds
	}

	// Extract user ID from refresh token
	sub, ok := refreshClaims["sub"].(string)
	if !ok {
		slog.Warn("Refresh token is missing 'sub' field", "userID", refreshClaims["sub"])
		return nil, models.ErrInvalidCreds
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		slog.Error("Failed to parse subject as UUID", "err", err)
		return nil, models.ErrInvalidCreds
	}

	t, err := s.st.GetUserTokens(ctx, pgtype.UUID{
		Bytes: userID,
		Valid: true,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("User has no stored tokens", "userID", userID)
		} else {
			slog.Error("Failed to get user tokens", "err", err, "userID", userID)
		}
	} else {
		if string(t.Token) != req.Token || string(t.RefreshToken) != req.RefreshToken {
			slog.Warn("Tokens do not match with stored", "userID", refreshClaims["sub"], "req", req)
			return nil, models.ErrInvalidCreds
		}
	}

	// Generate new tokens
	newToken, newRefresh, err := s.generateTokens(&models.User{ID: userID})
	if err != nil {
		slog.Error("Failed to generate tokens", "err", err, "userID", userID)
		return nil, errors.New("failed to refresh tokens")
	}

	// Store new tokens
	err = s.st.SaveUserTokens(ctx, postgres.SaveUserTokensParams{
		UserID:       pgtype.UUID{Bytes: userID, Valid: true},
		Token:        []byte(newToken),
		RefreshToken: []byte(newRefresh),
	})
	if err != nil {
		slog.Error("Failed to save new tokens", "err", err)
		return nil, errors.New("failed to refresh tokens")
	}

	slog.Debug("Tokens refreshed successfully", "userID", refreshClaims["sub"])

	return &models.UserLoginResponse{
		Token:        newToken,
		RefreshToken: newRefresh,
	}, nil
}

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

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing 'exp' field")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// generateTokens generates access and refresh tokens signed with a key from config.
func (s *Service) generateTokens(u *models.User) (string, string, error) {
	signingKey := []byte(s.cfg.JWT_SIGNING_KEY)

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}).SignedString(signingKey)
	if err != nil {
		slog.Error("Failed to generate token", "err", err, "userID", u.ID)
		return "", "", err
	}

	refresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	}).SignedString(signingKey)
	if err != nil {
		slog.Error("Failed to generate token", "err", err, "userID", u.ID)
		return "", "", err
	}

	return token, refresh, nil
}
