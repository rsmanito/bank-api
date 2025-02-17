package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rsmanito/bank-api/config"
	"github.com/stretchr/testify/assert"
)

var jwtSigningKey = config.Load().JWT_SIGNING_KEY

func createJWTToken(signingKey string, expireIn time.Duration, subject string) string {
	claims := jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(expireIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(signingKey))
	return signedToken
}

type MockServer struct {
	JWTSigningKey string
}

func setupTestServer() *fiber.App {
	app := fiber.New()
	app.Use(JWTTokenSuppliedMiddleware)
	app.Get("/test", func(c fiber.Ctx) error {
		userId := c.Context().Value("userId")
		return c.JSON(fiber.Map{"userId": userId})
	})
	return app
}

func TestJWT_MissingToken(t *testing.T) {
	app := setupTestServer()
	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var resBody map[string]string
	json.NewDecoder(resp.Body).Decode(&resBody)
	assert.Equal(t, "missing token", resBody["error"])
}

func TestJWT_BadTokenFormat(t *testing.T) {
	app := setupTestServer()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidToken") // Bad format

	resp, _ := app.Test(req)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var resBody map[string]string
	json.NewDecoder(resp.Body).Decode(&resBody)
	assert.Equal(t, "bad token format", resBody["error"])
}

func TestJWT_ExpiredToken(t *testing.T) {
	app := setupTestServer()
	userID := uuid.New()
	expiredToken := createJWTToken(jwtSigningKey, -1*time.Hour, userID.String()) // Expired

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	resp, _ := app.Test(req)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var resBody map[string]string
	json.NewDecoder(resp.Body).Decode(&resBody)
	assert.Equal(t, "expired token", resBody["error"])
}

func TestJWT_ValidToken(t *testing.T) {
	app := setupTestServer()
	userID := uuid.New()
	validToken := createJWTToken(jwtSigningKey, 1*time.Hour, userID.String()) // Valid

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, _ := app.Test(req)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var resBody map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&resBody)

	assert.Equal(t, userID.String(), resBody["userId"])
}
