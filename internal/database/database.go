package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/joho/godotenv/autoload"
)

// mockgen -source=internal/database/database.go -destination=internal/database/mocks/mock_database.go -package=mocks
type DbService interface {
	// Health returns a map of health status information.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error

	// Pool returns the underlying pgxpool connection pool.
	Pool() *pgxpool.Pool
}

type service struct {
	pool *pgxpool.Pool
}

var (
	database   = os.Getenv("DB_DATABASE")
	password   = os.Getenv("DB_PASSWORD")
	username   = os.Getenv("DB_USERNAME")
	port       = os.Getenv("DB_PORT")
	host       = os.Getenv("DB_HOST")
	dbInstance *service
)

func New() DbService {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}

	// Préparation de l'URL de connexion
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		// fallback pour tests/integration si DATABASE_URL n'est pas fourni
		if host == "" || port == "" || username == "" || database == "" {
			log.Fatalf("DATABASE_URL not set and DB variables missing (host/port/username/database)")
		}
		connStr = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			username, password, host, port, database)
	}

	// Configuration du pool avec des options personnalisées
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Unable to parse pool config: %v", err)
	}

	// Paramétrage du pool
	config.MaxConns = 75                       // Connexions max simultanées
	config.MinConns = 10                       // Connexions min maintenues
	config.MaxConnLifetime = 1 * time.Hour     // Durée de vie max d'une connexion
	config.MaxConnIdleTime = 30 * time.Minute  // Temps max d'inactivité
	config.HealthCheckPeriod = 1 * time.Minute // Vérification de la santé de la connexion

	// Création du pool avec la configuration personnalisée
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v", err)
	}

	// Test de la connexion
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	log.Printf("Successfully connected to database: %s", database)

	dbInstance = &service{
		pool: pool,
	}
	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.pool.Ping(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Printf("db down: %v", err) // Log the error but don't terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get pgxpool stats
	poolStats := s.pool.Stat()
	stats["total_connections"] = strconv.Itoa(int(poolStats.TotalConns()))
	stats["acquired_connections"] = strconv.Itoa(int(poolStats.AcquiredConns()))
	stats["idle_connections"] = strconv.Itoa(int(poolStats.IdleConns()))
	stats["max_connections"] = strconv.Itoa(int(poolStats.MaxConns()))

	// Évaluer les stats pour fournir un message de santé
	if int(poolStats.TotalConns()) > int(float64(poolStats.MaxConns())*0.8) {
		stats["message"] = "The database pool is nearing capacity."
	}

	if poolStats.AcquiredConns() > poolStats.IdleConns()*3 {
		stats["message"] = "High ratio of active to idle connections, consider increasing pool size."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
func (s *service) Close() error {
	log.Printf("Disconnecting from database: %s", database)
	s.pool.Close()
	return nil
}

// Pool returns the underlying pgxpool connection pool.
func (s *service) Pool() *pgxpool.Pool {
	return s.pool
}
