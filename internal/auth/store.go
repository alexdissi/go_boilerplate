package auth

import (
	"context"
	"errors"
	"fmt"
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
		return fmt.Errorf("failed to build create user query: %w", err)
	}

	err = s.pool.QueryRow(ctx, query, args...).Scan(&user.ID)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *Store) CheckUserEmailExists(ctx context.Context, email string) (bool, error) {
	query, args, err := sq.
		Select("1").
		From("users").
		Where(sq.Eq{"email": email}).
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("failed to build email check query: %w", err)
	}

	var dummy int
	err = s.pool.QueryRow(ctx, query, args...).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return true, nil
}

func (s *Store) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "password_hash", "first_name", "last_name", "profile_picture", "created_at", "updated_at",
			"last_login_at", "is_active", "activation_token", "two_factor_enabled", "two_factor_secret", "recovery_codes", "oauth_provider").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	var user user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.ProfilePicture, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
		&user.IsActive, &user.ActivationToken, &user.TwoFactorEnabled, &user.TwoFactorSecret, &user.RecoveryCodes, &user.OAuthProvider,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan user data: %w", err)
	}

	return &user, nil
}

func (s *Store) FindUserBySession(ctx context.Context, token string) (*user.User, error) {
	query, args, err := sq.
		Select("u.id", "u.email", "u.password_hash", "u.first_name", "u.last_name",
			"u.profile_picture", "u.created_at", "u.updated_at", "u.last_login_at",
			"u.is_active", "u.activation_token", "u.two_factor_enabled",
			"u.two_factor_secret", "u.recovery_codes").
		From("users u").
		Join("sessions s ON u.id = s.user_id").
		Where(sq.Eq{"s.session_token": token}).
		Where(sq.Expr("s.expires_at > NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build user by session query: %w", err)
	}

	var u user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.ProfilePicture, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		&u.IsActive, &u.ActivationToken, &u.TwoFactorEnabled, &u.TwoFactorSecret, &u.RecoveryCodes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by session: %w", err)
	}
	return &u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, token, ip, userAgent string, expiresAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	deleteQuery, deleteArgs, err := sq.
		Delete("sessions").
		Where(sq.Eq{"user_id": userID}).
		Where(sq.Expr("expires_at <= NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build delete expired sessions query: %w", err)
	}

	_, err = tx.Exec(ctx, deleteQuery, deleteArgs...)
	if err != nil {
		return fmt.Errorf("failed to clean user expired sessions: %w", err)
	}

	insertQuery, insertArgs, err := sq.
		Insert("sessions").
		Columns("user_id", "session_token", "ip_address", "user_agent", "expires_at", "created_at").
		Values(userID, token, ip, userAgent, expiresAt, nowUTC()).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build create session query: %w", err)
	}

	_, err = tx.Exec(ctx, insertQuery, insertArgs...)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit session creation transaction: %w", err)
	}

	return nil
}

func (s *Store) CleanExpiredSessions(ctx context.Context) error {
	query, args, err := sq.
		Delete("sessions").
		Where(sq.Expr("expires_at <= NOW()")).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build cleanup query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to clean expired sessions: %w", err)
	}
	return nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	query, args, err := sq.
		Delete("sessions").
		Where(sq.Eq{"session_token": token}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build delete session query: %w", err)
	}

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
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
		return fmt.Errorf("failed to build update last login query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

func (s *Store) FindUserByActivationToken(ctx context.Context, token string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "password_hash", "first_name", "last_name", "profile_picture",
			"created_at", "updated_at", "last_login_at", "is_active", "activation_token").
		From("users").
		Where(sq.Eq{"activation_token": token, "is_active": false}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build find user by activation token query: %w", err)
	}

	var u user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.ProfilePicture, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		&u.IsActive, &u.ActivationToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by activation token: %w", err)
	}

	return &u, nil
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
		return fmt.Errorf("failed to build activate user account query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to activate user account: %w", err)
	}

	return nil
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
		return fmt.Errorf("failed to build save reset password token query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to save reset password token: %w", err)
	}

	return nil
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
		return nil, fmt.Errorf("failed to build find user by reset token query: %w", err)
	}

	var u user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.ProfilePicture, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		&u.IsActive, &u.ActivationToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by reset token: %w", err)
	}

	return &u, nil
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
		return fmt.Errorf("failed to build update user password query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	return nil
}

func (s *Store) IncrementLoginAttempts(ctx context.Context, email string) (int, error) {
	query, args, err := sq.
		Update("users").
		Set("login_attempts", sq.Expr("login_attempts + 1")).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"email": email}).
		Suffix("RETURNING login_attempts").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("failed to build increment login attempts query: %w", err)
	}

	var attempts int
	err = s.pool.QueryRow(ctx, query, args...).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("failed to increment login attempts: %w", err)
	}
	return attempts, nil
}

func (s *Store) ResetLoginAttempts(ctx context.Context, email string) error {
	query, args, err := sq.
		Update("users").
		Set("login_attempts", 0).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"email": email}).
		Suffix("RETURNING id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build reset login attempts query: %w", err)
	}

	var userID uuid.UUID
	err = s.pool.QueryRow(ctx, query, args...).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}
	return nil
}

func (s *Store) GetLoginAttempts(ctx context.Context, email string) (int, error) {
	query, args, err := sq.
		Select("login_attempts").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("failed to build get login attempts query: %w", err)
	}

	var attempts int
	err = s.pool.QueryRow(ctx, query, args...).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("failed to get login attempts: %w", err)
	}

	return attempts, nil
}

func (s *Store) DeleteAllUserSessions(ctx context.Context, userID string) error {
	query, args, err := sq.
		Delete("sessions").
		Where(sq.Eq{"user_id": userID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build delete all user sessions query: %w", err)
	}

	_, err = s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete all user sessions: %w", err)
	}

	return nil
}

func (s *Store) FindUserByGoogleID(ctx context.Context, googleID string) (*user.User, error) {
	query, args, err := sq.
		Select("id", "email", "first_name", "last_name", "created_at", "two_factor_enabled", "oauth_provider", "google_id", "profile_picture").
		From("users").
		Where(sq.Eq{"google_id": googleID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build find user by google ID query: %w", err)
	}

	var u user.User
	err = s.pool.QueryRow(ctx, query, args...).Scan(
		&u.ID, &u.Email, &u.FirstName, &u.LastName,
		&u.CreatedAt, &u.TwoFactorEnabled,
		&u.OAuthProvider, &u.GoogleID, &u.ProfilePicture,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by google ID: %w", err)
	}

	return &u, nil
}

func (s *Store) CreateGoogleUser(ctx context.Context, u *user.User) error {
	query, args, err := sq.
		Insert("users").
		Columns("email", "first_name", "last_name", "google_id", "oauth_provider", "profile_picture", "created_at", "updated_at").
		Values(u.Email, u.FirstName, u.LastName, u.GoogleID, u.OAuthProvider, u.ProfilePicture, u.CreatedAt, nowUTC()).
		Suffix("RETURNING id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build create google user query: %w", err)
	}

	err = s.pool.QueryRow(ctx, query, args...).Scan(&u.ID)
	if err != nil {
		return fmt.Errorf("failed to create google user: %w", err)
	}

	return nil
}

func (s *Store) UpdateGoogleUserInfo(ctx context.Context, userID uuid.UUID, firstName, lastName, profilePicture string) error {
	query, args, err := sq.
		Update("users").
		Set("first_name", firstName).
		Set("last_name", lastName).
		Set("profile_picture", profilePicture).
		Set("updated_at", nowUTC()).
		Where(sq.Eq{"id": userID}).
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
		return ErrUserNotFound
	}
	return nil
}
