package auth

import (
	"context"
	"encoding/json"
	"os"
	"time"
	"whatsapp/internal/config"
	"whatsapp/internal/user"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthService struct {
	config *config.Config
	store  AuthStore
}

func NewOAuthService(cfg *config.Config, store AuthStore) *OAuthService {
	return &OAuthService{
		config: cfg,
		store:  store,
	}
}

func (s *OAuthService) GetGoogleOAuthConfig() *oauth2.Config {
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

func (s *OAuthService) HandleGoogleCallback(ctx context.Context, code, state, ip, userAgent string) (*user.User, *string, error) {
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
