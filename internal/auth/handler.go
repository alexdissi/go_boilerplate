package auth

import (
	"net/http"
	"time"
	"whatsapp/internal/config"
	"whatsapp/internal/middleware"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

type Handler struct {
	service *Service
	cfg     *config.Config
}

func NewHandler(service *Service, cfg *config.Config) *Handler {
	return &Handler{
		service: service,
		cfg:     cfg,
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

}

func (h *Handler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	user, err := h.service.Register(ctx, req)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusCreated, user)
}

func (h *Handler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	user, token, err := h.service.Login(ctx, req, ip, userAgent)
	if err != nil {
		return WriteError(c, err)
	}

	h.setSessionCookie(c, *token, h.cfg.Auth.SessionTTL)
	return c.JSON(http.StatusOK, user)
}

func (h *Handler) Logout(c echo.Context) error {
	ctx := c.Request().Context()
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "not authenticated"})
	}

	cookie, err := c.Cookie(h.cfg.Cookie.Name)
	if err != nil || cookie.Value == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "session missing"})
	}

	h.service.Logout(ctx, cookie.Value)
	h.clearSessionCookie(c)

	return c.JSON(http.StatusOK, echo.Map{"message": "logged out"})
}

func (h *Handler) ActivateAccount(c echo.Context) error {
	var req ActivateAccountRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request format"})
	}

	ctx := c.Request().Context()
	err := h.service.ActivateAccount(ctx, req.Token)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "account activated"})
}

func (h *Handler) ForgotPassword(c echo.Context) error {
	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request format"})
	}

	err := h.service.ForgotPassword(c.Request().Context(), req.Email, c.RealIP())
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "reset email sent"})
}

func (h *Handler) ResetPassword(c echo.Context) error {
	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid request format"})
	}

	err := h.service.ResetPassword(c.Request().Context(), req.Token, req.Password)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "password reset successfully"})
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

func (h *Handler) GoogleAuth(c echo.Context) error {
	config := h.service.GetGoogleOAuthConfig()
	if config == nil || config.ClientID == "" || config.ClientSecret == "" {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "OAuth configuration missing"})
	}

	state := uuid.NewString()

	// Store state in secure cookie for CSRF validation
	c.SetCookie(&http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	return c.JSON(http.StatusOK, echo.Map{"auth_url": url})
}

func (h *Handler) GoogleCallback(c echo.Context) error {
	ctx := c.Request().Context()
	code := c.QueryParam("code")
	state := c.QueryParam("state")
	errorParam := c.QueryParam("error")

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

	// Validate CSRF state
	stateCookie, err := c.Cookie("oauth_state")
	if err != nil || stateCookie.Value == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "Invalid OAuth state",
			"code":  "INVALID_STATE",
		})
	}

	if stateCookie.Value != state {
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "OAuth state mismatch",
			"code":  "STATE_MISMATCH",
		})
	}

	// Delete state cookie after validation
	c.SetCookie(&http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})

	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	_, sessionToken, err := h.service.HandleGoogleCallback(ctx, code, state, ip, userAgent)
	if err != nil {
		return WriteError(c, err)
	}

	if sessionToken == nil || *sessionToken == "" {
		return WriteError(c, ErrInternalError)
	}

	h.setSessionCookie(c, *sessionToken, h.cfg.Auth.SessionTTL)

	return c.Redirect(http.StatusTemporaryRedirect, h.cfg.AppURL)
}
