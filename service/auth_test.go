package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rsmanito/bank-api/models"

	"github.com/rsmanito/bank-api/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type MockStorage interface {
	CreateUser(context.Context, postgres.CreateUserParams) error
	GetUserByEmail(context.Context, string) (postgres.User, error)
	SaveUserTokens(context.Context, postgres.SaveUserTokensParams) error
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

func TestRegisterUser_Success(t *testing.T) {
	mockStore := new(MockStore)
	svc := &Service{st: mockStore}

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
	svc := &Service{st: mockStore}

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
	svc := &Service{st: mockStore}

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
	svc := &Service{st: mockStore}

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
	svc := &Service{st: mockStore}

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
