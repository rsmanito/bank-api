package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/rsmanito/bank-api/models"
	"github.com/rsmanito/bank-api/service"
	"github.com/rsmanito/bank-api/storage"
)

type Server struct {
	service *service.Service
	router  *fiber.App
}

// New returns a new Server.
func New(st *storage.Storage) *Server {
	server := &Server{
		service: service.New(st),
		router: fiber.New(fiber.Config{
			StructValidator: &models.StructValidator{Validator: validator.New()},
		}),
	}

	server.registerRoutes()

	return server
}

func (s *Server) registerRoutes() {
	s.router.Post("/auth/register", s.handleRegister)
	s.router.Post("/auth/login", s.handleLogin)
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

	token, err := s.service.LoginUser(c.Context(), r)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCreds) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"token": token})
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type apiError struct {
	Error string `json:"error"`
}

func makeHTTPHandler(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		}
	}
}
