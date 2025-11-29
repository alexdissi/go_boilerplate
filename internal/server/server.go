package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
	"whatsapp/internal/database"
	"whatsapp/internal/middleware"

	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
)

type Server struct {
	port   int
	db     database.DbService
	router *echo.Echo
}

func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	s := &Server{
		port: port,
		db:   database.New(),
	}

	// Crée Echo et configure toutes les routes
	e := echo.New()
	s.router = e // <-- important pour les handlers

	// Initialise le middleware de session avec la DB
	middleware.InitSessionMiddleware(s.db.Pool())

	// Configure middlewares et routes
	s.RegisterRoutes()

	// Démarre Echo comme http.Handler
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      e, // <-- ici tu passes Echo, pas e.RegisterRoutes()
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
