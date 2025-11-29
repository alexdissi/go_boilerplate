package auth

import (
	"context"
	crand "crypto/rand"
	"encoding/base32"
	"fmt"
	mrand "math/rand"
	"time"
	"whatsapp/internal/mailer"
	"whatsapp/internal/user"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

//go:generate mockgen -source=service.go -destination=./auth_service_mock.go -package=auth
type AuthStore interface {
	CheckUserEmailExists(ctx context.Context, email string) (bool, error)
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	CreateUser(ctx context.Context, user *user.User) error
	FindUserBySession(ctx context.Context, token string) (*user.User, error)
	CreateSession(ctx context.Context, userID, token, ip, userAgent string, expiresAt time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteAllUserSessions(ctx context.Context, userID string) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	FindUserByActivationToken(ctx context.Context, token string) (*user.User, error)
	ActivateUserAccount(ctx context.Context, userID uuid.UUID) error
	SaveResetPasswordToken(ctx context.Context, userID, token string) error
	FindUserByResetToken(ctx context.Context, token string) (*user.User, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
	IncrementLoginAttempts(ctx context.Context, email string) error
	ResetLoginAttempts(ctx context.Context, email string) error
	GetLoginAttempts(ctx context.Context, email string) (int, error)
	EnableTOTP(ctx context.Context, userID uuid.UUID, secret string, recoveryCodes []string) error
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
}

type Service struct {
	s      AuthStore
	mailer mailer.Mailer
}

func NewService(store AuthStore, mailer mailer.Mailer) *Service {
	return &Service{s: store, mailer: mailer}
}

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*user.User, error) {
	if !IsValidEmail(req.Email) {
		return nil, ErrEmailInvalid
	}

	if !IsStrongPassword(req.Password) {
		return nil, ErrPasswordWeak
	}

	exists, _ := s.s.CheckUserEmailExists(ctx, req.Email)
	if exists {
		return nil, ErrUserExists
	}

	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	activationToken, err := GenerateToken()
	if err != nil {
		return nil, err
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
		return nil, err
	}

	go func() {
		mailer.SendWelcomeEmail(ctx, s.mailer, newUser.Email, newUser.FirstName, newUser.LastName, activationToken)
	}()

	return newUser, nil
}

const maxLoginAttempts = 5

func (s *Service) Login(ctx context.Context, req LoginRequest, ip, userAgent string) (*user.User, *string, error) {
	attempts, err := s.s.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= maxLoginAttempts {
		return nil, nil, ErrTooManyAttempts
	}

	user, err := s.s.FindByEmail(ctx, req.Email)
	if err != nil || !ComparePassword(user.PasswordHash, req.Password) {
		s.s.IncrementLoginAttempts(ctx, req.Email)
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		s.s.IncrementLoginAttempts(ctx, req.Email)
		return nil, nil, ErrAccountNotActivated
	}

	s.s.ResetLoginAttempts(ctx, req.Email)

	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)

	if err := s.s.CreateSession(ctx, user.ID.String(), sessionToken, ip, userAgent, expiresAt); err != nil {
		return nil, nil, ErrInternalError
	}

	s.s.UpdateLastLogin(ctx, user.ID)
	return user, &sessionToken, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.s.DeleteSession(ctx, token)
}

func (s *Service) ActivateAccount(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	user, err := s.s.FindUserByActivationToken(ctx, token)
	if err != nil {
		return ErrInvalidToken
	}

	s.s.ActivateUserAccount(ctx, user.ID)
	return nil
}

func (s *Service) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.s.FindByEmail(ctx, email)
	if err != nil {
		return ErrUserNotFound
	}

	token, err := GenerateToken()
	if err != nil {
		return ErrInternalError
	}

	s.s.SaveResetPasswordToken(ctx, user.ID.String(), token)

	go func() {
		mailer.SendResetPasswordEmail(ctx, s.mailer, user.Email, user.FirstName+" "+user.LastName, token)
	}()

	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if token == "" || password == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindUserByResetToken(ctx, token)
	if err != nil {
		return ErrInvalidToken
	}

	hashedPassword, _ := HashPassword(password)
	if err := s.s.UpdateUserPassword(ctx, user.ID, hashedPassword); err != nil {
		return err
	}

	s.s.DeleteAllUserSessions(ctx, user.ID.String())
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
	for i := 0; i < 10; i++ {
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
		return nil, ErrUserNotFound
	}

	if !ComparePassword(user.PasswordHash, password) {
		return nil, ErrInvalidCredentials
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		return nil, ErrInternalError
	}

	qrCode, err := generateQRCode(secret, userEmail)
	if err != nil {
		return nil, ErrInternalError
	}

	recoveryCodes := generateRecoveryCodes()

	return &TOTPSetupResponse{
		Secret:     secret,
		QRCode:     qrCode,
		BackupCodes: recoveryCodes,
	}, nil
}

func (s *Service) EnableTOTP(ctx context.Context, userEmail, token, secret string, recoveryCodes []string) error {
	if token == "" || secret == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindByEmail(ctx, userEmail)
	if err != nil {
		return ErrUserNotFound
	}

	if !totp.Validate(token, secret) {
		return ErrInvalidToken
	}

	return s.s.EnableTOTP(ctx, user.ID, secret, recoveryCodes)
}

func (s *Service) DisableTOTP(ctx context.Context, userEmail, password, token string) error {
	if password == "" || token == "" {
		return ErrInvalidInput
	}

	user, err := s.s.FindByEmail(ctx, userEmail)
	if err != nil {
		return ErrUserNotFound
	}

	if !ComparePassword(user.PasswordHash, password) {
		return ErrInvalidCredentials
	}

	if !user.TwoFactorEnabled || user.TwoFactorSecret == nil {
		return ErrTOTPNotEnabled
	}

	if !totp.Validate(token, *user.TwoFactorSecret) {
		return ErrInvalidToken
	}

	return s.s.DisableTOTP(ctx, user.ID)
}

func (s *Service) LoginWithTOTP(ctx context.Context, req LoginWithTOTPRequest, ip, userAgent string) (*user.User, *string, error) {
	attempts, err := s.s.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= maxLoginAttempts {
		return nil, nil, ErrTooManyAttempts
	}

	user, err := s.s.FindByEmail(ctx, req.Email)
	if err != nil || !ComparePassword(user.PasswordHash, req.Password) {
		s.s.IncrementLoginAttempts(ctx, req.Email)
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		s.s.IncrementLoginAttempts(ctx, req.Email)
		return nil, nil, ErrAccountNotActivated
	}

	if user.TwoFactorEnabled && user.TwoFactorSecret != nil {
		if !totp.Validate(req.TOTPToken, *user.TwoFactorSecret) {
			s.s.IncrementLoginAttempts(ctx, req.Email)
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

	if err := s.s.CreateSession(ctx, user.ID.String(), sessionToken, ip, userAgent, expiresAt); err != nil {
		return nil, nil, ErrInternalError
	}

	s.s.UpdateLastLogin(ctx, user.ID)
	return user, &sessionToken, nil
}
