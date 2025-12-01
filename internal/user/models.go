package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                     uuid.UUID  `json:"id" db:"id"`
	Email                  string     `json:"email" db:"email"`
	PasswordHash           string     `json:"-" db:"password_hash"`
	FirstName              string     `json:"first_name" db:"first_name"`
	LastName               string     `json:"last_name" db:"last_name"`
	ProfilePicture         *string    `json:"profile_picture" db:"profile_picture"`
	IsActive               bool       `json:"is_active" db:"is_active"`
	ActivationToken        *string    `json:"-" db:"activation_token"`
	TwoFactorEnabled       bool       `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret        *string    `json:"-" db:"two_factor_secret"`
	RecoveryCodes          []string   `json:"-" db:"recovery_codes"`
	IsResettingPassword    bool       `json:"is_resetting_password" db:"is_resetting_password"`
	ResetPasswordToken     *string    `json:"-" db:"reset_password_token"`
	ResetPasswordExpiresAt *time.Time `json:"-" db:"reset_password_expires_at"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt            *time.Time `json:"last_login_at" db:"last_login_at"`
	GoogleID               *string    `json:"google_id" db:"google_id"`
	OAuthProvider          string     `json:"oauth_provider" db:"oauth_provider"`
}

type UserResponse struct {
	ID             uuid.UUID  `json:"id"`
	Email          string     `json:"email"`
	FirstName      string     `json:"first_name"`
	LastName       string     `json:"last_name"`
	ProfilePicture *string    `json:"profile_picture"`
	CreatedAt      time.Time  `json:"created_at"`
	LastLoginAt    *time.Time `json:"last_login_at"`
}

type Session struct {
	ID           uuid.UUID `json:"id" db:"id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	SessionToken string    `json:"-" db:"session_token"`
	IPAddress    *string   `json:"ip_address" db:"ip_address"`
	UserAgent    *string   `json:"user_agent" db:"user_agent"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}
