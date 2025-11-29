package auth

import (
	"context"
	"errors"
	"time"
	"whatsapp/internal/user"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func nowUTC() time.Time { return time.Now().UTC() }

func (s *Store) CreateUser(ctx context.Context, user *user.User) error {
	query, args, err := sq.
		Insert("users").
		Columns("email", "first_name", "last_name", "profile_picture", "password_hash", "created_at", "updated_at", "is_active", "activation_token").
		Values(user.Email, user.FirstName, user.LastName, user.ProfilePicture, user.PasswordHash, user.CreatedAt, user.UpdatedAt, user.IsActive, user.ActivationToken).
		Suffix("RETURNING id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, query, args...).Scan(&user.ID)
}

func (s *Store) CheckUserEmailExists(ctx context.Context, email string) (bool, error) {
	query, args, err := sq.
		Select("EXISTS (SELECT 1 FROM users WHERE email = $1)").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return false, err
	}
	var exists bool
	s.pool.QueryRow(ctx, query, args...).Scan(&exists)
	return exists, nil
}

func (s *Store) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "password_hash", "first_name", "last_name", "profile_picture", "created_at", "updated_at",
			"last_login_at", "is_active", "activation_token", "two_factor_enabled", "two_factor_secret", "recovery_codes").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, err
	}

	var user user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.ProfilePicture, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.IsActive, &user.ActivationToken, &user.TwoFactorEnabled, &user.TwoFactorSecret, &user.RecoveryCodes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

func (s *Store) FindUserBySession(ctx context.Context, token string) (*user.User, error) {
	query, args, err := sq.
		Select("u.id", "u.email", "u.password_hash", "u.first_name", "u.last_name", "u.profile_picture",
			"u.created_at", "u.updated_at", "u.last_login_at", "u.is_active", "u.activation_token",
			"u.two_factor_enabled", "u.two_factor_secret", "u.recovery_codes").
		From("sessions s").
		Join("users u ON u.id = s.user_id").
		Where(sq.Eq{"s.session_token": token}).
		Where(sq.Expr("s.expires_at > NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, err
	}

	var user user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.ProfilePicture, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.IsActive, &user.ActivationToken, &user.TwoFactorEnabled, &user.TwoFactorSecret, &user.RecoveryCodes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

func (s *Store) CreateSession(ctx context.Context, userID, token, ip, userAgent string, expiresAt time.Time) error {
	// Nettoyer les anciennes sessions expirées
	deleteQuery, deleteArgs, err := sq.
		Delete("sessions").
		Where(sq.Eq{"user_id": userID}).
		Where(sq.Expr("expires_at <= NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	s.pool.Exec(ctx, deleteQuery, deleteArgs...)

	// Créer la nouvelle session
	query, args, err := sq.
		Insert("sessions").
		Columns("user_id", "session_token", "ip_address", "user_agent", "expires_at", "created_at").
		Values(userID, token, ip, userAgent, expiresAt, nowUTC()).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	query, args, err := sq.
		Delete("sessions").
		Where(sq.Eq{"session_token": token}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (s *Store) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	query, args, err := sq.
		Update("users").
		Set("last_login_at", nowUTC()).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) FindUserByActivationToken(ctx context.Context, token string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "password_hash", "first_name", "last_name", "profile_picture",
			"created_at", "updated_at", "last_login_at", "is_active", "activation_token").
		From("users").
		Where(sq.Eq{"activation_token": token}).
		Where(sq.Eq{"is_active": false}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, err
	}

	var user user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.ProfilePicture, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.IsActive, &user.ActivationToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

func (s *Store) ActivateUserAccount(ctx context.Context, userID uuid.UUID) error {
	query, args, err := sq.
		Update("users").
		Set("is_active", true).
		Set("activation_token", nil).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) SaveResetPasswordToken(ctx context.Context, userID, token string) error {
	query, args, err := sq.
		Update("users").
		Set("reset_password_token", token).
		Set("reset_password_expires_at", nowUTC().Add(1*time.Hour)).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) FindUserByResetToken(ctx context.Context, token string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "password_hash", "first_name", "last_name", "profile_picture",
			"created_at", "updated_at", "last_login_at", "is_active", "activation_token").
		From("users").
		Where(sq.Eq{"reset_password_token": token}).
		Where(sq.Expr("reset_password_expires_at > NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, err
	}

	var user user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.ProfilePicture, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.IsActive, &user.ActivationToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	query, args, err := sq.
		Update("users").
		Set("password_hash", hashedPassword).
		Set("reset_password_token", nil).
		Set("reset_password_expires_at", nil).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) IncrementLoginAttempts(ctx context.Context, email string) error {
	query, args, err := sq.
		Update("users").
		Set("login_attempts", sq.Expr("login_attempts + 1")).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) ResetLoginAttempts(ctx context.Context, email string) error {
	query, args, err := sq.
		Update("users").
		Set("login_attempts", 0).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) GetLoginAttempts(ctx context.Context, email string) (int, error) {
	query, args, err := sq.
		Select("login_attempts").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return 0, err
	}
	var attempts int
	err = s.pool.QueryRow(ctx, query, args...).Scan(&attempts)
	return attempts, err
}

func (s *Store) DeleteAllUserSessions(ctx context.Context, userID string) error {
	query, args, err := sq.
		Delete("sessions").
		Where(sq.Eq{"user_id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, userID uuid.UUID, secret string, recoveryCodes []string) error {
	query, args, err := sq.
		Update("users").
		Set("two_factor_enabled", true).
		Set("two_factor_secret", secret).
		Set("recovery_codes", recoveryCodes).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}

func (s *Store) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	query, args, err := sq.
		Update("users").
		Set("two_factor_enabled", false).
		Set("two_factor_secret", nil).
		Set("recovery_codes", nil).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, query, args...)
	return err
}
