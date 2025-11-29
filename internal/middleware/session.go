package middleware

import (
	"net/http"
	"os"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

var dbPool *pgxpool.Pool

func InitSessionMiddleware(pool *pgxpool.Pool) {
	dbPool = pool
}

func CookieSessionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("session_token")
			if err != nil || cookie.Value == "" {
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "missing session token",
				})
			}

			sessionToken := cookie.Value
			ctx := c.Request().Context()

			query, args, err := sq.
				Select("u.id", "u.email").
				From("sessions s").
				Join("users u ON u.id = s.user_id").
				Where(sq.Eq{"s.session_token": sessionToken}).
				Where(sq.Expr("s.expires_at > NOW()")).
				PlaceholderFormat(sq.Dollar).
				ToSql()

			if err != nil {
				return c.JSON(http.StatusInternalServerError, echo.Map{
					"error": "failed to build query",
				})
			}

			var userID, email string
			err = dbPool.QueryRow(ctx, query, args...).Scan(&userID, &email)
			if err != nil {
				clearCookie := &http.Cookie{
					Name:     "session_token",
					Value:    "",
					Path:     "/",
					HttpOnly: true,
					Secure:   os.Getenv("APP_ENV") == "production",
					MaxAge:   -1,
				}
				c.SetCookie(clearCookie)
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid or expired session",
				})
			}

			c.Set("session_token", sessionToken)
			c.Set("user_id", userID)
			c.Set("email", email)

			return next(c)
		}
	}
}
