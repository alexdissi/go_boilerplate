package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"whatsapp/internal/config"
	"whatsapp/internal/errors"
	"whatsapp/internal/mailer"
	"whatsapp/internal/user"

	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	FindUserByGoogleID(ctx context.Context, googleID string) (*user.User, error)
	CreateGoogleUser(ctx context.Context, user *user.User) error
	UpdateGoogleUserInfo(ctx context.Context, userID uuid.UUID, firstName, lastName, profilePicture string) error
}

type Service struct {
	store  AuthStore
	mailer mailer.Mailer
	config *config.Config
	cache  gcache.Cache
}

func NewService(store AuthStore, mailer mailer.Mailer, cfg *config.Config) *Service {
	return &Service{
		store:  store,
		mailer: mailer,
		config: cfg,
		cache:  gcache.New(1000).LRU().Build(),
	}
}

const maxLoginAttempts = 5
const resetPasswordCooldown = 1 * time.Minute

func (s *Service) Register(ctx context.Context, req RegisterRequest) (*user.User, error) {
	existingUser, err := s.store.FindByEmail(ctx, req.Email)
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

	if err := s.store.CreateUser(ctx, newUser); err != nil {
		errors.WithStack(err)
		return nil, ErrInternalError
	}

	go s.sendWelcomeEmail(ctx, newUser.Email, newUser.FirstName, newUser.LastName, activationToken)

	return newUser, nil
}

func (s *Service) sendWelcomeEmail(ctx context.Context, email, firstName, lastName, token string) {
	defer func() {
		if r := recover(); r != nil {
			errors.WithStack(fmt.Errorf("welcome email panic: %v", r))
		}
	}()
	if err := mailer.SendWelcomeEmail(ctx, s.mailer, email, firstName, lastName, token); err != nil {
		errors.WithStack(err)
	}
}

func (s *Service) Login(ctx context.Context, req LoginRequest, ip, userAgent string) (*user.User, *string, error) {
	attempts, err := s.store.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= maxLoginAttempts {
		return nil, nil, ErrTooManyAttempts
	}

	user, err := s.store.FindByEmail(ctx, req.Email)
	if err != nil {
		s.store.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	valid, err := comparePassword(user.PasswordHash, req.Password)
	if err != nil || !valid {
		s.store.IncrementLoginAttempts(ctx, req.Email)
		errors.WithStack(err)
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		s.store.IncrementLoginAttempts(ctx, req.Email)
		return nil, nil, ErrAccountNotActivated
	}

	s.store.ResetLoginAttempts(ctx, req.Email)

	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)

	if err := s.store.CreateSession(ctx, user.ID, sessionToken, ip, userAgent, expiresAt); err != nil {
		errors.WithStack(err)
		return nil, nil, ErrInternalError
	}

	return user, &sessionToken, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}
	return s.store.DeleteSession(ctx, token)
}

func (s *Service) ActivateAccount(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	user, err := s.store.FindUserByActivationToken(ctx, token)
	if err != nil {
		return ErrInvalidToken
	}

	if err := s.store.ActivateUserAccount(ctx, user.ID); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) ForgotPassword(ctx context.Context, email, ip string) error {
	_, err := s.cache.Get(email)
	if err == nil {
		return ErrTooManyAttempts
	}

	user, err := s.store.FindByEmail(ctx, email)
	if err != nil {
		return ErrUserNotFound
	}

	token, err := GenerateToken()
	if err != nil {
		errors.WithStack(err)
		return ErrInternalError
	}

	if err := s.store.SaveResetPasswordToken(ctx, user.ID.String(), token); err != nil {
		errors.WithStack(err)
		return ErrInternalError
	}

	// Marquer la demande avec expiration automatique
	s.cache.SetWithExpire(email, true, resetPasswordCooldown)

	go s.sendResetPasswordEmail(ctx, user.Email, user.FirstName+" "+user.LastName, token)

	return nil
}

func (s *Service) sendResetPasswordEmail(ctx context.Context, email, fullName, token string) {
	defer func() {
		if r := recover(); r != nil {
			errors.WithStack(fmt.Errorf("password reset email panic: %v", r))
		}
	}()
	if err := mailer.SendResetPasswordEmail(ctx, s.mailer, email, fullName, token); err != nil {
		errors.WithStack(err)
	}
}

func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if token == "" || password == "" {
		return ErrInvalidInput
	}

	user, err := s.store.FindUserByResetToken(ctx, token)
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

	if err := s.store.UpdateUserPassword(ctx, user.ID, hashedPassword); err != nil {
		errors.WithStack(err)
		return err
	}

	if err := s.store.DeleteAllUserSessions(ctx, user.ID.String()); err != nil {
		errors.WithStack(err)
		return err
	}

	return nil
}

func (s *Service) FindUserBySession(ctx context.Context, token string) (*user.User, error) {
	return s.store.FindUserBySession(ctx, token)
}

func (s *Service) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	return s.store.FindByEmail(ctx, email)
}

func (s *Service) GetGoogleOAuthConfig() *oauth2.Config {
	if s.config == nil {
		return nil
	}
	redirectURL := "http://localhost:8080/auth/google/callback"
	return &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     google.Endpoint,
	}
}

func (s *Service) HandleGoogleCallback(ctx context.Context, code, state, ip, userAgent string) (*user.User, *string, error) {
	if code == "" {
		return nil, nil, ErrInvalidInput
	}

	config := s.GetGoogleOAuthConfig()
	if config == nil {
		return nil, nil, ErrInternalError
	}

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	client := config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, nil, ErrInternalError
	}
	defer resp.Body.Close()

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, nil, ErrInternalError
	}

	if userInfo.Email == "" || userInfo.ID == "" {
		return nil, nil, ErrInternalError
	}

	_, err = s.store.FindUserByGoogleID(ctx, userInfo.ID)
	if err != nil && err != ErrUserNotFound {
		return nil, nil, ErrInternalError
	}

	existingUser, err := s.store.FindByEmail(ctx, userInfo.Email)
	if err != nil && err != ErrUserNotFound {
		return nil, nil, ErrInternalError
	}

	if existingUser != nil {
		return nil, nil, ErrUserExists
	}

	provider := GoogleProvider
	newUser := &user.User{
		Email:          userInfo.Email,
		FirstName:      userInfo.Given,
		LastName:       userInfo.Family,
		ProfilePicture: &userInfo.Picture,
		GoogleID:       &userInfo.ID,
		OAuthProvider:  provider,
		IsActive:       true,
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.store.CreateGoogleUser(ctx, newUser); err != nil {
		return nil, nil, ErrInternalError
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)

	if err := s.store.CreateSession(ctx, newUser.ID, sessionToken, ip, userAgent, expiresAt); err != nil {
		return nil, nil, ErrInternalError
	}

	return newUser, &sessionToken, nil
}
