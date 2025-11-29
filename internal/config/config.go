package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	Environment string
	AppURL      string
	APIURL      string
	Cookie      CookieConfig
	Auth        AuthConfig
	CORS        CORSConfig
}

type CookieConfig struct {
	Domain     string
	SessionTTL time.Duration
	Name       string
}

type AuthConfig struct {
	SessionTTL time.Duration
}

type CORSConfig struct {
	AllowOrigins []string
}

func Load() *Config {
	return &Config{
		Environment: getEnv("APP_ENV", "development"),
		AppURL:      getEnv("APP_URL", "http://localhost:8080"),
		APIURL:      getEnv("API_URL", "http://localhost:8080"),
		Cookie: CookieConfig{
			Domain:     getEnv("COOKIE_DOMAIN", ""),
			SessionTTL: 15 * 24 * time.Hour, // 15 days
			Name:       "session_token",
		},
		Auth: AuthConfig{
			SessionTTL: 15 * 24 * time.Hour, // 15 days
		},
		CORS: CORSConfig{
			AllowOrigins: getEnvSlice("CORS_ORIGINS", []string{
				"https://figenn.com",
				"https://app.figenn.com",
				"https://www.app.figenn.com",
				"https://www.figenn.com",
				"http://localhost:3000",
			}),
		},
	}
}

func (c *Config) IsProd() bool {
	return strings.EqualFold(c.Environment, "production")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}