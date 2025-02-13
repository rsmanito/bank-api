package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) JWTTokenSuppliedMiddleware(c fiber.Ctx) error {
	h := c.Get("Authorization")
	if h == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing token"})
	}
	split := strings.Split(c.Get("Authorization"), " ")
	if split[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "bad token format"})
	}

	token, err := jwt.Parse(split[1], func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(s.cfg.JWT_SIGNING_KEY), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "expired token"})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "bad token format"})
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		c.SetContext(
			context.WithValue(c.Context(), "userId", claims["sub"]),
		)
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
	}

	err = c.Next()

	return err
}
