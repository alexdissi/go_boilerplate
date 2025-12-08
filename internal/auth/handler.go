package auth

import (
	"net/http"
	"strings"
	"time"
	"whatsapp/internal/config"
	"whatsapp/internal/middleware"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type Handler struct {
	s   *Service
	cfg *config.Config
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		s:   service,
		cfg: config.Load(),
	}
}

func (h *Handler) Bind(rg *echo.Group) {
	rg.POST("/register", h.Register)
	rg.POST("/login", h.Login)
	rg.POST("/activate", h.ActivateAccount)
	rg.POST("/forgot-password", h.ForgotPassword)
	rg.POST("/reset-password", h.ResetPassword)
	rg.DELETE("/logout", h.Logout, middleware.CookieSessionMiddleware())

	rg.GET("/google/auth", h.GoogleAuth)
	rg.GET("/google/callback", h.GoogleCallback)

	rg.POST("/totp/setup", h.SetupTOTP, middleware.CookieSessionMiddleware())
	rg.POST("/totp/enable", h.EnableTOTP, middleware.CookieSessionMiddleware())
	rg.POST("/totp/disable", h.DisableTOTP, middleware.CookieSessionMiddleware())
	rg.POST("/totp/login", h.LoginWithTOTP)
}

func (h *Handler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	user, err := h.s.Register(ctx, req)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusCreated, user)
}

func (h *Handler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	user, token, err := h.s.Login(ctx, req, ip, userAgent)
	if err != nil {
		return WriteError(c, err)
	}

	h.setSessionCookie(c, *token, h.cfg.Auth.SessionTTL)
	return c.JSON(http.StatusOK, user)
}

func (h *Handler) Logout(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || strings.TrimSpace(userID) == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}

	sessionToken := ""
	if cookie, err := c.Cookie(h.cfg.Cookie.Name); err == nil {
		sessionToken = cookie.Value
	}

	if sessionToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "session missing"})
	}

	h.s.Logout(c.Request().Context(), sessionToken)
	h.clearSessionCookie(c)

	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *Handler) ActivateAccount(c echo.Context) error {
	var req ActivateAccountRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	err := h.s.ActivateAccount(ctx, req.Token)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "account activated",
	})
}

func (h *Handler) ForgotPassword(c echo.Context) error {
	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	err := h.s.ForgotPassword(c.Request().Context(), req.Email)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "reset email sent"})
}

func (h *Handler) ResetPassword(c echo.Context) error {
	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	err := h.s.ResetPassword(c.Request().Context(), req.Token, req.Password)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "password reset successfully"})
}

func (h *Handler) setSessionCookie(c echo.Context, value string, ttl time.Duration) {
	cookie := &http.Cookie{
		Name:     h.cfg.Cookie.Name,
		Value:    value,
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().UTC().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	}
	http.SetCookie(c.Response(), cookie)
}

func (h *Handler) clearSessionCookie(c echo.Context) {
	http.SetCookie(c.Response(), &http.Cookie{
		Name:     h.cfg.Cookie.Name,
		Value:    "",
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})
}

func (h *Handler) SetupTOTP(c echo.Context) error {
	var req TOTPSetupRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}

	email, ok := c.Get("email").(string)
	if !ok || email == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid session"})
	}

	ctx := c.Request().Context()
	resp, err := h.s.SetupTOTP(ctx, email, req.Password)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *Handler) EnableTOTP(c echo.Context) error {
	var req TOTPEnableRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}

	email, ok := c.Get("email").(string)
	if !ok || email == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid session"})
	}

	// Récupérer l'utilisateur complet pour accéder aux champs TOTP
	user, err := h.s.FindByEmail(ctx, email)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid session"})
	}

	if user.TwoFactorEnabled {
		return c.JSON(http.StatusConflict, map[string]string{"error": "TOTP is already enabled"})
	}

	secret := user.TwoFactorSecret
	if secret == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "TOTP not set up"})
	}

	err = h.s.EnableTOTP(ctx, email, req.Token, *secret, user.RecoveryCodes)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "TOTP enabled successfully"})
}

func (h *Handler) DisableTOTP(c echo.Context) error {
	var req TOTPDisableRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}

	email, ok := c.Get("email").(string)
	if !ok || email == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid session"})
	}

	err := h.s.DisableTOTP(c.Request().Context(), email, req.Password, req.Token)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "TOTP disabled successfully"})
}

func (h *Handler) LoginWithTOTP(c echo.Context) error {
	var req LoginWithTOTPRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	user, token, err := h.s.LoginWithTOTP(ctx, req, ip, userAgent)
	if err != nil {
		return WriteError(c, err)
	}

	var sessionTTL time.Duration
	if req.RememberMe {
		sessionTTL = 30 * 24 * time.Hour
	} else {
		sessionTTL = 24 * time.Hour
	}

	h.setSessionCookie(c, *token, sessionTTL)
	return c.JSON(http.StatusOK, user)
}

func (h *Handler) GoogleAuth(c echo.Context) error {
	oauthService := NewOAuthService(h.cfg, h.s.s)
	config := oauthService.GetGoogleOAuthConfig()
	if config == nil || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "OAuth configuration missing required fields"})
	}

	state := uuid.NewString()
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	return c.JSON(http.StatusOK, echo.Map{"auth_url": url})
}

func (h *Handler) GoogleCallback(c echo.Context) error {
	ctx := c.Request().Context()
	code := strings.TrimSpace(c.QueryParam("code"))
	state := strings.TrimSpace(c.QueryParam("state"))
	errorParam := strings.TrimSpace(c.QueryParam("error"))

	if errorParam != "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":   "OAuth authorization denied",
			"code":    "OAUTH_DENIED",
			"details": errorParam,
		})
	}

	if code == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error": "Authorization code missing",
			"code":  "CODE_MISSING",
		})
	}

	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	oauthService := NewOAuthService(h.cfg, h.s.s)
	_, sessionToken, err := oauthService.HandleGoogleCallback(ctx, code, state, ip, userAgent)
	if err != nil {
		return WriteError(c, err)
	}

	if sessionToken == nil || *sessionToken == "" {
		return WriteError(c, ErrInternalError)
	}

	h.setSessionCookie(c, *sessionToken, h.cfg.Auth.SessionTTL)

	return c.Redirect(http.StatusTemporaryRedirect, h.cfg.AppURL)
}
