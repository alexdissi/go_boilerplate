package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

var (
	ErrInvalidInput        = errors.New("invalid input data")
	ErrEmailInvalid        = errors.New("invalid email format")
	ErrPasswordWeak        = errors.New("password is too weak (8-72 characters, 1 uppercase, 1 digit, 1 special character)")
	ErrUserExists          = errors.New("user already exists")
	ErrGoogleOAuthExists   = errors.New("email already registered with Google account")
	ErrUserNotFound        = errors.New("user not found")
	ErrAccountNotActivated = errors.New("account not activated")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInternalError       = errors.New("internal server error")
	ErrInvalidTOTPToken    = errors.New("invalid TOTP token")
	ErrTOTPAlreadyEnabled  = errors.New("TOTP is already enabled")
	ErrTOTPNotEnabled      = errors.New("TOTP is not enabled")
	ErrSessionNotFound     = errors.New("session not found")
	ErrTooManyAttempts     = errors.New("too many login attempts")
)

type errorResponse struct {
	statusCode int
	message    string
}

var errorMap = map[error]errorResponse{
	ErrInvalidInput:        {http.StatusBadRequest, "Invalid input data"},
	ErrEmailInvalid:        {http.StatusBadRequest, "Invalid email format"},
	ErrPasswordWeak:        {http.StatusBadRequest, "Password is too weak (8-72 characters, 1 uppercase, 1 digit, 1 special character)"},
	ErrUserExists:          {http.StatusConflict, "User already exists"},
	ErrGoogleOAuthExists:   {http.StatusConflict, "Email already registered with Google account. Please use Google to sign in"},
	ErrInvalidCredentials:  {http.StatusUnauthorized, "Invalid credentials"},
	ErrAccountNotActivated: {http.StatusForbidden, "Account not activated, please check your email for activation link"},
	ErrUserNotFound:        {http.StatusNotFound, "User not found"},
	ErrInvalidToken:        {http.StatusUnauthorized, "Invalid token, please request a new password reset link"},
	ErrInternalError:       {http.StatusInternalServerError, "Internal server error, please try again later"},
	ErrInvalidTOTPToken:    {http.StatusBadRequest, "Invalid TOTP code"},
	ErrTOTPAlreadyEnabled:  {http.StatusConflict, "TOTP is already enabled"},
	ErrTOTPNotEnabled:      {http.StatusBadRequest, "TOTP is not enabled"},
	ErrSessionNotFound:     {http.StatusNotFound, "Session not found"},
	ErrTooManyAttempts:     {http.StatusTooManyRequests, "Too many failed login attempts. Account temporarily locked. Try again later"},
}

func WriteError(c echo.Context, err error) error {
	if resp, ok := errorMap[err]; ok {
		return c.JSON(resp.statusCode, echo.Map{"error": resp.message})
	}
	return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error, please try again later"})
}
