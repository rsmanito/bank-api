package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type MockStorage interface {
	CreateUser(context.Context, postgres.CreateUserParams) error
	GetUserByEmail(context.Context, string) (postgres.User, error)
	GetUserById(context.Context, pgtype.UUID) (postgres.User, error)
	SaveUserTokens(context.Context, postgres.SaveUserTokensParams) error
	GetUserTokens(context.Context, pgtype.UUID) (postgres.Token, error)
	CreateCard(context.Context, postgres.CreateCardParams) error
	CardNumberExists(context.Context, string) (bool, error)
}

type MockStore struct {
	mock.Mock
}

func (m *MockStore) CreateUser(ctx context.Context, params postgres.CreateUserParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockStore) SaveUserTokens(ctx context.Context, params postgres.SaveUserTokensParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (postgres.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(postgres.User), args.Error(1)
}

func (m *MockStore) GetUserById(ctx context.Context, userId pgtype.UUID) (postgres.User, error) {
	args := m.Called(ctx, userId)
	return args.Get(0).(postgres.User), args.Error(1)
}

func (m *MockStore) GetUserTokens(ctx context.Context, userId pgtype.UUID) (postgres.Token, error) {
	args := m.Called(ctx, userId)
	return args.Get(0).(postgres.Token), args.Error(1)
}

func (m *MockStore) GetUserCards(ctx context.Context, userId pgtype.UUID) ([]postgres.Card, error) {
	args := m.Called(ctx, userId)
	return args.Get(0).([]postgres.Card), args.Error(1)
}

func (m *MockStore) CreateCard(ctx context.Context, params postgres.CreateCardParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockStore) CardNumberExists(ctx context.Context, number string) (bool, error) {
	args := m.Called(ctx, number)
	return args.Get(0).(bool), args.Error(1)
}

func TestRegisterUser_Success(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	req := &models.RegisterUserRequest{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
		Password:  "password123",
	}

	mockStore.
		On("CreateUser", mock.Anything, mock.MatchedBy(func(p postgres.CreateUserParams) bool {
			var id uuid.UUID
			if err := id.UnmarshalBinary(p.ID.Bytes[:]); err != nil {
				return false
			}

			if p.Email != req.Email {
				return false
			}

			err := bcrypt.CompareHashAndPassword(p.Password, []byte(req.Password))
			return err == nil
		})).
		Return(nil).
		Once()

	err := svc.RegisterUser(context.Background(), req)
	assert.NoError(t, err)

	mockStore.AssertExpectations(t)
}

func TestRegisterUser_CreateUserError(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	req := &models.RegisterUserRequest{
		FirstName: "Jane",
		LastName:  "Doe",
		Email:     "jane@example.com",
		Password:  "strongpassword",
	}

	expectedErr := errors.New("create user failed")
	mockStore.
		On("CreateUser", mock.Anything, mock.AnythingOfType("postgres.CreateUserParams")).
		Return(expectedErr).
		Once()

	err := svc.RegisterUser(context.Background(), req)
	assert.EqualError(t, err, expectedErr.Error())

	mockStore.AssertExpectations(t)
}

func TestLoginUser_LoginSuccess(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	req := &models.LoginUserRequest{
		Email:    "test@example.com",
		Password: "stongpassword",
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)

	mockStore.
		On("GetUserByEmail", mock.Anything, req.Email).
		Return(postgres.User{
			Password: hashedPassword,
		}, nil).
		Once()

	mockStore.
		On("SaveUserTokens", mock.Anything, mock.AnythingOfType("postgres.SaveUserTokensParams")).
		Return(nil).
		Once()

	res, err := svc.LoginUser(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, res.Token)
	assert.NotNil(t, res.RefreshToken)

	mockStore.AssertExpectations(t)
}

func TestLoginUser_GetUserByEmailError(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	req := &models.LoginUserRequest{
		Email: "test@example.com",
	}

	expectedErr := errors.New("get user failed")

	mockStore.
		On("GetUserByEmail", mock.Anything, req.Email).
		Return(postgres.User{}, errors.New("get user failed")).
		Once()

	res, err := svc.LoginUser(context.Background(), req)

	assert.EqualError(t, err, expectedErr.Error())

	assert.Nil(t, res)
}

func TestLoginUser_InvalidCreds(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	req := &models.LoginUserRequest{
		Email:    "test@example.com",
		Password: "password",
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)

	mockStore.
		On("GetUserByEmail", mock.Anything, req.Email).
		Return(postgres.User{
			Password: hashedPassword,
		}, nil).
		Once()

	req.Password = "wrongpassword"

	res, err := svc.LoginUser(context.Background(), req)

	assert.EqualError(t, err, models.ErrInvalidCreds.Error())

	assert.Nil(t, res)
}

// helper to create a JWT string with given claims and signing key.
func createJWT(claims jwt.MapClaims, signingKey string) string {
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
	if err != nil {
		panic(fmt.Sprintf("failed to create token: %v", err))
	}
	return tokenStr
}

func TestRefreshToken_AccessTokenStillValid(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	// Create valid tokens.
	accessClaims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	refreshClaims := jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	accessToken := createJWT(accessClaims, svc.cfg.JWT_SIGNING_KEY)
	refreshToken := createJWT(refreshClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}

	// Should return original tokens without calling SaveUserTokens.
	res, err := svc.RefreshToken(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, accessToken, res.Token)
	assert.Equal(t, refreshToken, res.RefreshToken)
}

func TestRefreshToken_ExpiredAccessValidRefresh(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	userID := uuid.New()
	// Create an expired access token.
	expiredAccessClaims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"sub": userID.String(),
	}
	// Create a valid refresh token.
	validRefreshClaims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}

	expiredAccessToken := createJWT(expiredAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	validRefreshToken := createJWT(validRefreshClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        expiredAccessToken,
		RefreshToken: validRefreshToken,
	}

	// GetUserTokens will be called with the correct userID.
	mockStore.
		On("GetUserTokens", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(postgres.Token{
			Token:        []byte(expiredAccessToken),
			RefreshToken: []byte(validRefreshToken),
		}, nil).
		Once()

	// SaveUserTokens will be called with a SaveUserTokensParams with the correct userID.
	mockStore.
		On("SaveUserTokens", mock.Anything, mock.MatchedBy(func(p postgres.SaveUserTokensParams) bool {
			return p.UserID.Valid && p.UserID.Bytes == userID
		})).
		Return(nil).
		Once()

	res, err := svc.RefreshToken(context.Background(), req)
	assert.NoError(t, err)

	// Should generate new tokens.
	// Should differ from the request tokens.
	assert.NotEqual(t, expiredAccessToken, res.Token)
	assert.NotEqual(t, validRefreshToken, res.RefreshToken)

	mockStore.AssertExpectations(t)
}

func TestRefreshToken_ExpiredRefreshToken(t *testing.T) {
	mockStore := new(MockStore)
	userID := uuid.New()
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	// Create expired access token.
	expiredAccessClaims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(-2 * time.Hour).Unix(),
	}
	// Create expired refresh token.
	expiredRefreshClaims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Add(-3 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}

	expiredAccessToken := createJWT(expiredAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	expiredRefreshToken := createJWT(expiredRefreshClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        expiredAccessToken,
		RefreshToken: expiredRefreshToken,
	}

	res, err := svc.RefreshToken(context.Background(), req)

	assert.ErrorIs(t, err, models.ErrTokensExpired)
	assert.Nil(t, res)
}

func TestRefreshToken_InvalidRefreshTokenSubject(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	// Create expired access token.
	expiredAccessClaims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	// Refresh token with invalid claims.
	invalidSubClaims := jwt.MapClaims{
		"sub": "not-a-uuid",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}

	expiredAccessToken := createJWT(expiredAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	invalidSubToken := createJWT(invalidSubClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        expiredAccessToken,
		RefreshToken: invalidSubToken,
	}

	res, err := svc.RefreshToken(context.Background(), req)
	assert.ErrorIs(t, err, models.ErrInvalidCreds)
	assert.Nil(t, res)
}

func TestRefreshToken_SaveTokensError(t *testing.T) {
	mockStore := new(MockStore)
	userID := uuid.New()
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	// Create an expired access token.
	expiredAccessClaims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	// Create a valid refresh token.
	validRefreshClaims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}

	expiredAccessToken := createJWT(expiredAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	validRefreshToken := createJWT(validRefreshClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        expiredAccessToken,
		RefreshToken: validRefreshToken,
	}

	// GetUserTokens will be called with the correct userID.
	mockStore.
		On("GetUserTokens", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(postgres.Token{
			Token:        []byte(expiredAccessToken),
			RefreshToken: []byte(validRefreshToken),
		}, nil).
		Once()

	// Database save fails.
	mockStore.
		On("SaveUserTokens", mock.Anything, mock.MatchedBy(func(p postgres.SaveUserTokensParams) bool {
			return p.UserID.Valid && p.UserID.Bytes == userID
		})).
		Return(errors.New("db error")).
		Once()

	res, err := svc.RefreshToken(context.Background(), req)
	assert.EqualError(t, err, "failed to refresh tokens")
	assert.Nil(t, res)

	mockStore.AssertExpectations(t)
}

func TestRefreshToken_TokensDontMatchStored(t *testing.T) {
	mockStore := new(MockStore)
	userID := uuid.New()
	svc := &Service{
		st:  mockStore,
		cfg: &config.Config{JWT_SIGNING_KEY: "supersecret"},
	}

	// Create an expired access token.
	expiredAccessClaims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	// Create a valid refresh token.
	validRefreshClaims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}

	expiredAccessToken := createJWT(expiredAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	validRefreshToken := createJWT(validRefreshClaims, svc.cfg.JWT_SIGNING_KEY)

	req := &models.RefreshTokenRequest{
		Token:        expiredAccessToken,
		RefreshToken: validRefreshToken,
	}

	// Generate different tokens than the request.
	storedAccessClaims := jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"foo": "bar",
	}
	storedRefreshClaims := jwt.MapClaims{
		"foo": "bar",
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}

	storedAccessToken := createJWT(storedAccessClaims, svc.cfg.JWT_SIGNING_KEY)
	storedRefreshToken := createJWT(storedRefreshClaims, svc.cfg.JWT_SIGNING_KEY)

	// GetUserTokens will return different tokens than the request.
	mockStore.
		On("GetUserTokens", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(postgres.Token{
			Token:        []byte(storedAccessToken),
			RefreshToken: []byte(storedRefreshToken),
		}, nil).
		Once()

	res, err := svc.RefreshToken(context.Background(), req)
	assert.ErrorIs(t, err, models.ErrInvalidCreds)
	assert.Nil(t, res)

	mockStore.AssertExpectations(t)
}

func TestGetMe_Success(t *testing.T) {
	mockStore := new(MockStore)
	userID := uuid.New()
	svc := &Service{
		st: mockStore,
	}

	mockStore.
		On("GetUserById", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(postgres.User{
			ID: pgtype.UUID{Bytes: userID, Valid: true},
		}, nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userID.String())
	_, err := svc.GetUser(ctx)

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestGetCards_NoCards(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userID := uuid.New()

	mockStore.
		On("GetUserCards", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(make([]postgres.Card, 0), nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userID.String())
	res, err := svc.GetUserCards(ctx)

	assert.NoError(t, err)
	assert.Equal(t, make([]*models.Card, 0), res)
	mockStore.AssertExpectations(t)
}

func TestGetCards_Success(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userID := uuid.New()

	expected := make([]postgres.Card, 2)

	mockStore.
		On("GetUserCards", mock.Anything, mock.MatchedBy(func(p pgtype.UUID) bool {
			return p.Valid && p.Bytes == userID
		})).
		Return(expected, nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userID.String())
	res, err := svc.GetUserCards(ctx)

	assert.NoError(t, err)
	assert.Equal(t, len(expected), len(res))

	mockStore.AssertExpectations(t)
}

func TestCreateCard_Success(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userId := uuid.New()

	req := &models.CreateCardRequest{
		Title:    "Title",
		Currency: "USD",
		Type:     "DEBIT",
	}

	mockStore.
		On("CardNumberExists", mock.Anything, mock.Anything).
		Return(false, nil)

	mockStore.
		On("CreateCard", mock.Anything, mock.MatchedBy(func(p postgres.CreateCardParams) bool {
			return (p.Holder.Bytes == userId &&
				p.Title.String == req.Title &&
				p.Currency == req.Currency &&
				p.Type == postgres.CardType(req.Type))
		})).
		Return(nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userId.String())

	res, err := svc.CreateCard(ctx, req)

	assert.NoError(t, err)

	assert.Equal(t, req.Title, res.Title)
	assert.Equal(t, req.Currency, res.Currency)
	assert.True(t, req.Type == string(res.Type))

	mockStore.AssertExpectations(t)
}

func TestCreateCard_NoTitle(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userId := uuid.New()

	req := &models.CreateCardRequest{
		Currency: "USD",
		Type:     "DEBIT",
	}

	mockStore.
		On("CardNumberExists", mock.Anything, mock.Anything).
		Return(false, nil)

	mockStore.
		On("CreateCard", mock.Anything, mock.MatchedBy(func(p postgres.CreateCardParams) bool {
			return (p.Holder.Bytes == userId &&
				p.Currency == req.Currency &&
				p.Type == postgres.CardType(req.Type))
		})).
		Return(nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userId.String())

	res, err := svc.CreateCard(ctx, req)

	assert.NoError(t, err)

	assert.Equal(t, "", res.Title)
	assert.Equal(t, req.Currency, res.Currency)
	assert.True(t, req.Type == string(res.Type))

	mockStore.AssertExpectations(t)
}

func TestCreateCard_NumberExists(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userId := uuid.New()

	req := &models.CreateCardRequest{
		Title:    "Title",
		Currency: "USD",
		Type:     "DEBIT",
	}

	// Model that 10 first card numbers are taken.
	mockStore.
		On("CardNumberExists", mock.Anything, mock.Anything).
		Return(true, nil).
		Times(10)

	mockStore.
		On("CardNumberExists", mock.Anything, mock.Anything).
		Return(false, nil).
		Once()

	mockStore.
		On("CreateCard", mock.Anything, mock.MatchedBy(func(p postgres.CreateCardParams) bool {
			return (p.Holder.Bytes == userId &&
				p.Title.String == req.Title &&
				p.Currency == req.Currency &&
				p.Type == postgres.CardType(req.Type))
		})).
		Return(nil).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userId.String())

	res, err := svc.CreateCard(ctx, req)

	assert.NoError(t, err)

	assert.Equal(t, req.Title, res.Title)
	assert.Equal(t, req.Currency, res.Currency)
	assert.True(t, req.Type == string(res.Type))

	mockStore.AssertExpectations(t)
}

func TestCreateCard_DbError(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{
		st: mockStore,
	}

	userId := uuid.New()

	req := &models.CreateCardRequest{
		Title:    "Title",
		Currency: "USD",
		Type:     "DEBIT",
	}

	mockStore.
		On("CardNumberExists", mock.Anything, mock.Anything).
		Return(false, errors.New("error")).
		Once()

	ctx := context.WithValue(context.Background(), "userId", userId.String())

	res, err := svc.CreateCard(ctx, req)

	assert.Error(t, err)
	assert.Errorf(t, err, "failed to create a card")
	assert.Nil(t, res)

	mockStore.AssertExpectations(t)
}
