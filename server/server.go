package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/service"
	"github.com/rsmanito/bank-api/storage"
)

type Service interface {
	RegisterUser(context.Context, *models.RegisterUserRequest) error
	LoginUser(context.Context, *models.LoginUserRequest) (*models.UserLoginResponse, error)
	RefreshToken(context.Context, *models.RefreshTokenRequest) (*models.UserLoginResponse, error)
}

type Server struct {
	service Service
	router  *fiber.App
}

// New returns a new Server.
func New(st *storage.Storage, cfg *config.Config) *Server {
	server := &Server{
		service: service.New(st, cfg),
		router: fiber.New(fiber.Config{
			StructValidator: &models.StructValidator{Validator: validator.New()},
		}),
	}

	server.registerRoutes()

	return server
}

func (s *Server) registerRoutes() {
	api := s.router.Group("/api/v1")
	auth := api.Group("/auth")
	{
		auth.Post("/register", s.handleRegister)
		auth.Post("/login", s.handleLogin)
		auth.Post("/refresh", s.handleRefreshToken)
	}
}

func (s *Server) Run(listenAddr string) {
	s.router.Listen(listenAddr)
}

func (s *Server) handleRegister(c fiber.Ctx) error {
	r := &models.RegisterUserRequest{}

	if err := c.Bind().JSON(r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return s.service.RegisterUser(c.Context(), r)
}

func (s *Server) handleLogin(c fiber.Ctx) error {
	r := &models.LoginUserRequest{}

	if err := c.Bind().JSON(r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	res, err := s.service.LoginUser(c.Context(), r)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCreds) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}

	return c.Status(http.StatusOK).JSON(res)
}

func (s *Server) handleRefreshToken(c fiber.Ctx) error {
	r := &models.RefreshTokenRequest{}

	if err := c.Bind().JSON(r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	res, err := s.service.RefreshToken(c.Context(), r)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(res)
}
