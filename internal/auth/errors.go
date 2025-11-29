package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

func WriteError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid input data"})
	case errors.Is(err, ErrEmailInvalid):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid email format"})
	case errors.Is(err, ErrPasswordWeak), errors.Is(err, ErrPasswordTooWeak):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Password is too weak (8+ characters, 1 uppercase, 1 digit, 1 special character)"})
	case errors.Is(err, ErrUserExists), errors.Is(err, ErrUserAlreadyExist):
		return c.JSON(http.StatusConflict, echo.Map{"error": "User already exists"})
	case errors.Is(err, ErrInvalidCredentials):
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid credentials"})
	case errors.Is(err, ErrEmailNotVerified):
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Email not verified, please check your inbox"})
	case errors.Is(err, ErrAccountNotActivated):
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Account not activated, please check your email for activation link"})
	case errors.Is(err, ErrMissingFields):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Some required fields are missing or invalid"})
	case errors.Is(err, ErrUserNotFound):
		return c.JSON(http.StatusNotFound, echo.Map{"error": "User not found"})
	case errors.Is(err, ErrTokenExpired):
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Token has expired, please request a new password reset link"})
	case errors.Is(err, ErrInvalidToken):
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token, please request a new password reset link"})
	case errors.Is(err, ErrInternalError), errors.Is(err, errors.New("internal server error, please try again later")):
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error, please try again later"})
	case errors.Is(err, ErrInvalidTOTPCode), errors.Is(err, ErrInvalidTOTPToken):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid TOTP code"})
	case errors.Is(err, ErrTOTPAlreadyEnabled):
		return c.JSON(http.StatusConflict, echo.Map{"error": "TOTP is already enabled"})
	case errors.Is(err, ErrTOTPNotEnabled):
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "TOTP is not enabled"})
	case errors.Is(err, ErrSessionNotFound):
		return c.JSON(http.StatusNotFound, echo.Map{"error": "Session not found"})
	case errors.Is(err, ErrTooManyAttempts):
		return c.JSON(http.StatusTooManyRequests, echo.Map{"error": "Too many failed login attempts. Account temporarily locked. Try again later"})
	default:
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error, please try again later"})
	}
}

var (
	ErrInvalidInput    = errors.New("invalid input data")
	ErrEmailInvalid    = errors.New("invalid email format")
	ErrPasswordWeak    = errors.New("password is too weak (8+ characters, 1 uppercase, 1 digit, 1 special character)")
	ErrPasswordTooWeak = errors.New("password is too weak (8+ characters, 1 uppercase, 1 digit, 1 special character)")
	ErrMissingFields   = errors.New("some required fields are missing or invalid")

	ErrUserAlreadyExist = errors.New("user already exists")
	ErrUserExists       = errors.New("user already exists")
	ErrUserNotFound     = errors.New("user not found")
	ErrEmailNotVerified = errors.New("email not verified, please check your inbox")
	ErrAccountNotActivated = errors.New("account not activated, please check your email for activation link")

	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token has expired, please request a new password reset link")
	ErrInvalidToken       = errors.New("invalid token, please request a new password reset link")

	ErrInternalError = errors.New("internal server error, please try again later")

	ErrInvalidTOTPCode    = errors.New("invalid TOTP code")
	ErrInvalidTOTPToken   = errors.New("invalid TOTP token")
	ErrTOTPAlreadyEnabled = errors.New("tOTP is already enabled")
	ErrTOTPNotEnabled     = errors.New("tOTP is not enabled")

	ErrSessionNotFound = errors.New("session not found")
	ErrTooManyAttempts = errors.New("too many login attempts")
)
