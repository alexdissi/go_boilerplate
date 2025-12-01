package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"whatsapp/internal/config"
	"whatsapp/internal/mailer"
	"whatsapp/internal/user"
)

// Mock mailer instance
type mockMailer struct{}

func (m *mockMailer) SendMail(ctx context.Context, cfg mailer.Config) (string, error) {
	return "test-id", nil
}

func setupTestService(t *testing.T) (*Service, *MockAuthStore) {
	ctrl := gomock.NewController(t)
	mockStore := NewMockAuthStore(ctrl)

	// Create test config
	cfg := &config.Config{
		Environment: "test",
		AppURL:      "http://localhost:8080",
		APIURL:      "http://localhost:8080",
		Auth: config.AuthConfig{
			SessionTTL: 24 * time.Hour,
		},
		Cookie: config.CookieConfig{
			Name:       "test_session",
			Domain:     "localhost",
			SessionTTL: 24 * time.Hour,
		},
		CORS: config.CORSConfig{
			AllowOrigins: []string{"http://localhost:3000"},
		},
	}

	// Create service
	service := &Service{
		s:      mockStore,
		mailer: &mockMailer{},
		config: cfg,
	}

	return service, mockStore
}

func TestNewService(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := NewMockAuthStore(ctrl)

	cfg := &config.Config{
		Environment: "test",
		AppURL:      "http://localhost:8080",
		APIURL:      "http://localhost:8080",
	}

	service := NewService(mockStore, &mockMailer{}, cfg)

	assert.NotNil(t, service)
	assert.Equal(t, mockStore, service.s)
	assert.Equal(t, cfg, service.config)
}

func TestService_Register_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	req := RegisterRequest{
		Email:     "test@example.com",
		Password:  "StrongPass123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Mock user not found
	mockStore.EXPECT().FindByEmail(ctx, req.Email).Return(nil, ErrUserNotFound)

	// Mock successful user creation
	mockStore.EXPECT().CreateUser(ctx, gomock.Any()).Return(nil)

	user, err := service.Register(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.Equal(t, req.FirstName, user.FirstName)
	assert.Equal(t, req.LastName, user.LastName)
	assert.False(t, user.IsActive)
	assert.NotNil(t, user.ActivationToken)
}

func TestService_Register_UserExists(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	req := RegisterRequest{
		Email:     "test@example.com",
		Password:  "StrongPass123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	existingUser := &user.User{
		Email:         req.Email,
		IsActive:      true,
		OAuthProvider: "",
	}

	// Mock user found
	mockStore.EXPECT().FindByEmail(ctx, req.Email).Return(existingUser, nil)

	user, err := service.Register(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, ErrUserExists, err)
	assert.Nil(t, user)
}

func TestService_Login_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	req := LoginRequest{
		Email:    "test@example.com",
		Password: "StrongPass123!",
	}

	hashedPass, _ := HashPassword(req.Password)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        req.Email,
		PasswordHash: hashedPass,
		IsActive:     true,
	}

	// Mock successful login flow
	mockStore.EXPECT().GetLoginAttempts(ctx, req.Email).Return(0, ErrUserNotFound)
	mockStore.EXPECT().FindByEmail(ctx, req.Email).Return(existingUser, nil)
	mockStore.EXPECT().ResetLoginAttempts(ctx, req.Email).Return(nil)
	mockStore.EXPECT().CreateSession(ctx, existingUser.ID, gomock.Any(), "127.0.0.1", gomock.Any(), gomock.Any()).Return(nil)

	user, token, err := service.Login(ctx, req, "127.0.0.1", "test-agent")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.NotNil(t, token)
	assert.Equal(t, existingUser.Email, user.Email)
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	req := LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	hashedPass, _ := HashPassword("correctpassword")
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        req.Email,
		PasswordHash: hashedPass,
		IsActive:     true,
	}

	// Mock failed login
	mockStore.EXPECT().GetLoginAttempts(ctx, req.Email).Return(0, ErrUserNotFound)
	mockStore.EXPECT().FindByEmail(ctx, req.Email).Return(existingUser, nil)
	mockStore.EXPECT().IncrementLoginAttempts(ctx, req.Email).Return(1, nil)

	user, token, err := service.Login(ctx, req, "127.0.0.1", "test-agent")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, user)
	assert.Nil(t, token)
}

func TestService_Logout_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "valid-session-token"

	// Mock successful logout
	mockStore.EXPECT().DeleteSession(ctx, token).Return(nil)

	err := service.Logout(ctx, token)

	assert.NoError(t, err)
}

func TestService_Logout_EmptyToken(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	err := service.Logout(ctx, "")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestService_ActivateAccount_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "valid-activation-token"
	userID := uuid.New()
	existingUser := &user.User{
		ID:              userID,
		Email:           "test@example.com",
		ActivationToken: &token,
		IsActive:        false,
	}

	// Mock successful activation
	mockStore.EXPECT().FindUserByActivationToken(ctx, token).Return(existingUser, nil)
	mockStore.EXPECT().ActivateUserAccount(ctx, userID).Return(nil)

	err := service.ActivateAccount(ctx, token)

	assert.NoError(t, err)
}

func TestService_ActivateAccount_EmptyToken(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	err := service.ActivateAccount(ctx, "")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestService_ActivateAccount_InvalidToken(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "invalid-token"

	// Mock user not found
	mockStore.EXPECT().FindUserByActivationToken(ctx, token).Return(nil, ErrUserNotFound)

	err := service.ActivateAccount(ctx, token)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestService_ForgotPassword_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	email := "test@example.com"
	existingUser := &user.User{
		ID:    uuid.New(),
		Email: email,
	}

	// Mock successful password reset request
	mockStore.EXPECT().FindByEmail(ctx, email).Return(existingUser, nil)
	mockStore.EXPECT().SaveResetPasswordToken(ctx, existingUser.ID.String(), gomock.Any()).Return(nil)

	err := service.ForgotPassword(ctx, email)

	assert.NoError(t, err)
}

func TestService_ForgotPassword_UserNotFound(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	email := "nonexistent@example.com"

	// Mock user not found
	mockStore.EXPECT().FindByEmail(ctx, email).Return(nil, ErrUserNotFound)

	err := service.ForgotPassword(ctx, email)

	assert.Error(t, err)
	assert.Equal(t, ErrUserNotFound, err)
}

func TestService_ResetPassword_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "valid-reset-token"
	newPassword := "NewStrongPass123!"
	userID := uuid.New()
	existingUser := &user.User{
		ID:       userID,
		Email:    "test@example.com",
		IsActive: true,
	}

	// Mock successful password reset
	mockStore.EXPECT().FindUserByResetToken(ctx, token).Return(existingUser, nil)
	mockStore.EXPECT().UpdateUserPassword(ctx, userID, gomock.Any()).Return(nil)
	mockStore.EXPECT().DeleteAllUserSessions(ctx, userID.String()).Return(nil)

	err := service.ResetPassword(ctx, token, newPassword)

	assert.NoError(t, err)
}

func TestService_ResetPassword_EmptyToken(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	err := service.ResetPassword(ctx, "", "newpassword")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidInput, err)
}

func TestService_ResetPassword_WeakPassword(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "valid-reset-token"
	weakPassword := "weak"
	userID := uuid.New()
	existingUser := &user.User{
		ID:       userID,
		Email:    "test@example.com",
		IsActive: true,
	}

	// Mock user found but password is weak
	mockStore.EXPECT().FindUserByResetToken(ctx, token).Return(existingUser, nil)

	err := service.ResetPassword(ctx, token, weakPassword)

	assert.Error(t, err)
	assert.Equal(t, ErrPasswordWeak, err)
}

func TestService_FindUserBySession_Success(t *testing.T) {
	service, mockStore := setupTestService(t)
	ctx := context.Background()

	token := "valid-session-token"
	existingUser := &user.User{
		ID:    uuid.New(),
		Email: "test@example.com",
	}

	// Mock successful user lookup
	mockStore.EXPECT().FindUserBySession(ctx, token).Return(existingUser, nil)

	user, err := service.FindUserBySession(ctx, token)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, existingUser.Email, user.Email)
}

func TestIsValidEmail(t *testing.T) {
	assert.True(t, IsValidEmail("test@example.com"))
	assert.True(t, IsValidEmail("user.name+tag@domain.co.uk"))
	assert.False(t, IsValidEmail("invalid-email"))
	assert.False(t, IsValidEmail("test@"))
	assert.False(t, IsValidEmail("@example.com"))
}

func TestIsStrongPassword(t *testing.T) {
	assert.True(t, IsStrongPassword("StrongPass123!"))
	assert.True(t, IsStrongPassword("MyP@ssw0rd"))
	assert.False(t, IsStrongPassword("weak"))
	assert.False(t, IsStrongPassword("nouppercase123!"))
	assert.False(t, IsStrongPassword("NOLOWERCASE123!"))
	assert.False(t, IsStrongPassword("NoDigits!"))
	assert.False(t, IsStrongPassword("NoSpecial123"))
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	assert.NoError(t, err)
	assert.Len(t, token1, 64)

	token2, err := GenerateToken()
	assert.NoError(t, err)
	assert.NotEqual(t, token1, token2)
}

func TestHashPassword(t *testing.T) {
	password := "TestPassword123!"
	hash, err := HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)

	// Test that hash follows expected format
	assert.Contains(t, hash, "$argon2id$")
}

func TestComparePassword(t *testing.T) {
	password := "TestPassword123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	assert.True(t, ComparePassword(hash, password))
	assert.False(t, ComparePassword(hash, "wrongpassword"))
	assert.False(t, ComparePassword("invalidhash", password))
}

func TestGenerateAvatarURL(t *testing.T) {
	firstName := "John"
	lastName := "Doe"

	url := GenerateAvatarURL(&firstName, &lastName)
	assert.Contains(t, url, "https://api.dicebear.com/9.x/initials/svg?seed=JD")

	// Test with nil names
	url = GenerateAvatarURL(nil, nil)
	assert.Equal(t, "https://api.dicebear.com/9.x/initials/svg?seed=", url)
}

// OAuth Service tests
func TestNewOAuthService(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := NewMockAuthStore(ctrl)

	service := NewOAuthService(nil, mockStore)
	assert.NotNil(t, service)
}

func TestOAuthService_GetGoogleOAuthConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := NewMockAuthStore(ctrl)

	cfg := &config.Config{
		Environment: "test",
		AppURL:      "http://localhost:8080",
		APIURL:      "http://localhost:8080",
	}

	service := NewOAuthService(cfg, mockStore)
	oauthConfig := service.GetGoogleOAuthConfig()

	assert.NotNil(t, oauthConfig)
	assert.Equal(t, "http://localhost:8080/auth/google/callback", oauthConfig.RedirectURL)
	assert.Equal(t, []string{"openid", "profile", "email"}, oauthConfig.Scopes)
}

func TestOAuthService_HandleGoogleCallback_InvalidCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := NewMockAuthStore(ctrl)
	service := NewOAuthService(nil, mockStore)

	ctx := context.Background()
	user, token, err := service.HandleGoogleCallback(ctx, "", "state", "127.0.0.1", "test-agent")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidInput, err)
	assert.Nil(t, user)
	assert.Nil(t, token)
}
