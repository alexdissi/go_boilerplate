package server

import (
	"net/http"
	"whatsapp/internal/auth"
	"whatsapp/internal/config"
	"whatsapp/internal/mailer"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

func (s *Server) RegisterRoutes() http.Handler {
	cfg := config.Load()
	e := s.router

	e.Use(echomiddleware.Logger())
	e.Use(echomiddleware.Recover())
	e.Use(echomiddleware.SecureWithConfig(echomiddleware.SecureConfig{
		XFrameOptions:         "DENY",
		ContentTypeNosniff:    "nosniff",
		XSSProtection:         "1; mode=block",
		HSTSMaxAge:            31536000,
		HSTSExcludeSubdomains: false,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;",
	}))
	e.Use(echomiddleware.CORSWithConfig(echomiddleware.CORSConfig{
		AllowOrigins:     cfg.CORS.AllowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	e.Use(echomiddleware.RateLimiterWithConfig(echomiddleware.RateLimiterConfig{
		Store: echomiddleware.NewRateLimiterMemoryStore(100),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return c.JSON(429, echo.Map{"error": "rate limit exceeded"})
		},
	}))

	e.Use(echomiddleware.BodyLimit("2MB"))

	e.GET("/", s.HelloWorldHandler)

	e.GET("/health", s.healthHandler)
	apiGroup := e.Group("")
	s.setupAuthRoutes(apiGroup)

	return e
}

func (s *Server) HelloWorldHandler(c echo.Context) error {
	resp := map[string]string{
		"message": "Hello World",
	}

	return c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
}

func (s *Server) setupAuthRoutes(apiGroup *echo.Group) {
	authStore := auth.NewStore(s.db.Pool())
	mailer := mailer.NewMailer()
	authService := auth.NewService(authStore, mailer)
	authHandler := auth.NewHandler(authService)

	authGroup := apiGroup.Group("/auth")
	authGroup.Use(echomiddleware.RateLimiterWithConfig(echomiddleware.RateLimiterConfig{
		Store: echomiddleware.NewRateLimiterMemoryStore(10),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return c.JSON(429, echo.Map{"error": "too many authentication attempts"})
		},
	}))

	authHandler.Bind(authGroup)
}
