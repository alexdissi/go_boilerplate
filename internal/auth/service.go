package auth

import (
	"context"
	crand "crypto/rand"
	"encoding/base32"
	"fmt"
	mrand "math/rand"
	"time"
	"whatsapp/internal/config"
	"whatsapp/internal/errors"
	"whatsapp/internal/mailer"
	"whatsapp/internal/user"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

//go:generate mockgen -source=service.go -destination=./auth_mock.go -package=auth
type AuthStore interface {
	CheckUserEmailExists(ctx context.Context, email string) (bool, error)
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	CreateUser(ctx context.Context, user *user.User) error
	FindUserBySession(ctx context.Context, token string) (*user.User, error)
	CreateSession(ctx context.Context, userID uuid.UUID, token, ip, userAgent string, expiresAt time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteAllUserSessions(ctx context.Context, userID string) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	FindUserByActivationToken(ctx context.Context, token string) (*user.User, error)
	ActivateUserAccount(ctx context.Context, userID uuid.UUID) error
	SaveResetPasswordToken(ctx context.Context, userID, token string) error
	FindUserByResetToken(ctx context.Context, token string) (*user.User, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
	IncrementLoginAttempts(ctx context.Context, email string) (int, error)
	ResetLoginAttempts(ctx context.Context, email string) error
	GetLoginAttempts(ctx context.Context, email string) (int, error)
	EnableTOTP(ctx context.Context, userID uuid.UUID, secret string, recoveryCodes []string) error
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
	FindUserByGoogleID(ctx context.Context, googleID string) (*user.User, error)
	CreateGoogleUser(ctx context.Context, user *user.User) error
	UpdateGoogleUserInfo(ctx context.Context, userID uuid.UUID, firstName, lastName, profilePicture string) error
}

type Service struct {
	s      AuthStore
	mailer mailer.Mailer
	config *config.Config
}

func NewService(store AuthStore, mailer mailer.Mailer, cfg *config.Config) *Service {
	return &Service{
		s:      store,
		mailer: mailer,
		config: cfg,
	}
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*user.User, error) {
	existingUser, err := s.s.FindByEmail(ctx, req.Email)
	if err == nil {
		if existingUser.OAuthProvider == GoogleProvider {
			return nil, ErrGoogleOAuthExists
		}
		return nil, ErrUserExists
	}

	if !IsValidEmail(req.Email) {
		return nil, ErrEmailInvalid
	}

	if !IsStrongPassword(req.Password) {
		return nil, ErrPasswordWeak
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	activationToken, err := GenerateToken()
	if err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	avatarURL := GenerateAvatarURL(&req.FirstName, &req.LastName)
	newUser := &user.User{
		Email:           req.Email,
		PasswordHash:    hashedPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		ProfilePicture:  &avatarURL,
		IsActive:        false,
		ActivationToken: &activationToken,
		CreatedAt:       time.Now().UTC(),
	}

	if err := s.s.CreateUser(ctx, newUser); err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errors.WithStack(fmt.Errorf("welcome email panic: %v", r))
			}
		}()
		if err := mailer.SendWelcomeEmail(ctx, s.mailer, newUser.Email, newUser.FirstName, newUser.LastName, activationToken); err != nil {
			errors.WithStack(err)
		}
	}()

	return newUser, nil
}

const maxLoginAttempts = 5

func (s *Service) Login(ctx context.Context, req LoginRequest, ip, userAgent string) (*user.User, *string, error) {
	attempts, err := s.s.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= maxLoginAttempts {
		errors.WithStack(err)
		return nil, nil, ErrTooManyAttempts
	}

	user, err := s.s.FindByEmail(ctx, req.Email)
	if err != nil {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	_, err = comparePassword(user.PasswordHash, req.Password)
	if err != nil {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrAccountNotActivated
	}

	s.s.ResetLoginAttempts(ctx, req.Email)

	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)

	if err := s.s.CreateSession(ctx, user.ID, sessionToken, ip, userAgent, expiresAt); err != nil {
		errors.WithStack(err)
		return nil, nil, ErrInternalError
	}

	return user, &sessionToken, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	if err := s.s.DeleteSession(ctx, token); err != nil {
		return err
	}

	return nil
}

func (s *Service) ActivateAccount(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	user, err := s.s.FindUserByActivationToken(ctx, token)
	if err != nil {
		return ErrInvalidToken
	}

	if err := s.s.ActivateUserAccount(ctx, user.ID); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.s.FindByEmail(ctx, email)
	if err != nil {
		return ErrUserNotFound
	}

	token, err := GenerateToken()
	if err != nil {
		errors.WithStack(err)
		return ErrInternalError
	}

	if err := s.s.SaveResetPasswordToken(ctx, user.ID.String(), token); err != nil {
		errors.WithStack(err)
		return ErrInternalError
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errors.WithStack(fmt.Errorf("password reset email panic: %v", r))
			}
		}()
		if err := mailer.SendResetPasswordEmail(ctx, s.mailer, user.Email, user.FirstName+" "+user.LastName, token); err != nil {
			errors.WithStack(err)
		}
	}()

	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if token == "" || password == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindUserByResetToken(ctx, token)
	if err != nil {
		errors.WithStack(err)
		return ErrInvalidToken
	}

	if !IsStrongPassword(password) {
		return ErrPasswordWeak
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		errors.WithStack(err)
		return ErrInternalError
	}

	if err := s.s.UpdateUserPassword(ctx, user.ID, hashedPassword); err != nil {
		errors.WithStack(err)
		return err
	}

	if err := s.s.DeleteAllUserSessions(ctx, user.ID.String()); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) FindUserBySession(ctx context.Context, token string) (*user.User, error) {
	return s.s.FindUserBySession(ctx, token)
}

func (s *Service) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	return s.s.FindByEmail(ctx, email)
}

func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := crand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func generateRecoveryCodes() []string {
	codes := make([]string, 10)
	for i := range 10 {
		codes[i] = fmt.Sprintf("%04d-%04d", mrand.Intn(10000), mrand.Intn(10000))
	}
	return codes
}

func generateQRCode(secret, userEmail string) (string, error) {
	otpURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		"WhatsApp App", userEmail, secret, "WhatsApp App")

	qrCode, err := qrcode.Encode(otpURL, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(qrCode), nil
}

func (s *Service) SetupTOTP(ctx context.Context, userEmail, password string) (*TOTPSetupResponse, error) {
	if password == "" {
		return nil, ErrInvalidInput
	}

	user, err := s.s.FindByEmail(ctx, userEmail)
	if err != nil {
		errors.WithStack(err)
		return nil, ErrUserNotFound
	}

	_, err = comparePassword(user.PasswordHash, password)
	if err != nil {
		errors.WithStack(fmt.Errorf("invalid password for user %s", user.ID.String()))
		return nil, ErrInvalidCredentials
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	qrCode, err := generateQRCode(secret, userEmail)
	if err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	recoveryCodes := generateRecoveryCodes()

	return &TOTPSetupResponse{
		Secret:      secret,
		QRCode:      qrCode,
		BackupCodes: recoveryCodes,
	}, nil
}

func (s *Service) EnableTOTP(ctx context.Context, userEmail, token, secret string, recoveryCodes []string) error {
	if token == "" || secret == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindByEmail(ctx, userEmail)
	if err != nil {
		errors.WithStack(err)
		return ErrUserNotFound
	}

	if !totp.Validate(token, secret) {
		errors.WithStack(fmt.Errorf("invalid TOTP token for user %s", user.ID.String()))
		return ErrInvalidToken
	}

	if err := s.s.EnableTOTP(ctx, user.ID, secret, recoveryCodes); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) DisableTOTP(ctx context.Context, userEmail, password, token string) error {
	if password == "" || token == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindByEmail(ctx, userEmail)
	if err != nil {
		errors.WithStack(err)
		return ErrUserNotFound
	}

	_, err = comparePassword(user.PasswordHash, password)
	if err != nil {
		errors.WithStack(fmt.Errorf("invalid password for user %s", user.ID.String()))
		return ErrInvalidCredentials
	}

	if !user.TwoFactorEnabled || user.TwoFactorSecret == nil {
		return ErrTOTPNotEnabled
	}

	if !totp.Validate(token, *user.TwoFactorSecret) {
		errors.WithStack(fmt.Errorf("invalid TOTP token for user %s", user.ID.String()))
		return ErrInvalidToken
	}

	if err := s.s.DisableTOTP(ctx, user.ID); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) LoginWithTOTP(ctx context.Context, req LoginWithTOTPRequest, ip, userAgent string) (*user.User, *string, error) {
	attempts, err := s.s.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= maxLoginAttempts {
		errors.WithStack(err)
		return nil, nil, ErrTooManyAttempts
	}

	user, err := s.s.FindByEmail(ctx, req.Email)
	if err != nil {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	_, err = comparePassword(user.PasswordHash, req.Password)
	if err != nil {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		_, _ = s.s.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(fmt.Errorf("account not activated for user %s", user.ID.String()))
		return nil, nil, ErrAccountNotActivated
	}

	if user.TwoFactorEnabled && user.TwoFactorSecret != nil {
		if !totp.Validate(req.TOTPToken, *user.TwoFactorSecret) {
			s.s.IncrementLoginAttempts(ctx, req.Email)
			errors.WithStack(fmt.Errorf("invalid TOTP token for user %s", user.ID.String()))
			return nil, nil, ErrInvalidTOTPToken
		}
	}

	s.s.ResetLoginAttempts(ctx, req.Email)

	var sessionTTL time.Duration
	if req.RememberMe {
		sessionTTL = 30 * 24 * time.Hour
	} else {
		sessionTTL = 24 * time.Hour
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(sessionTTL)

	if err := s.s.CreateSession(ctx, user.ID, sessionToken, ip, userAgent, expiresAt); err != nil {
		errors.WithStack(err)
		return nil, nil, ErrInternalError
	}

	if err := s.s.UpdateLastLogin(ctx, user.ID); err != nil {
		errors.WithStack(err)
	}

	return user, &sessionToken, nil
}
