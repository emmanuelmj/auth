package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"

	"github.com/jackc/pgx/v5"
)

func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), nil
}

func (a *Auth) LoginUser(username, password string) error {
	if a.Conn == nil {
		return ErrDatabaseUnavailable
	}

	var storedHash, storedSalt sql.NullString
	query := "SELECT password_hash, salt FROM users WHERE user_id = $1"
	err := a.Conn.QueryRow(context.Background(), query, username).Scan(&storedHash, &storedSalt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return ErrUserNotFound
	}
	if !storedHash.Valid || !storedSalt.Valid {
		return ErrInvalidCredentials
	}

	if !a.comparePasswords(password, storedSalt.String, storedHash.String) {
		return ErrInvalidCredentials
	}

	return nil
}

/*
LoginJWT validates a token string by calling auth.ValidateToken (JWT login).
This is the recommended way to validate a user's JWT.
It returns the claims if the token is valid.
*/
func (a *Auth) LoginJWT(tokenString string) (*JWTClaims, error) {
	/*
		We call ValidateToken from jwt.go to handle the logic.
		This keeps all user login methods in users.go, but all
		JWT logic in jwt.go.
	*/
	return a.ValidateToken(tokenString)
}

func (a *Auth) LoginWithGoogle(ctx context.Context, gUser *GoogleUser) (string, error) {
	if a.Conn == nil {
		return "", ErrDatabaseUnavailable
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	if gUser == nil {
		return "", ErrInvalidInput
	}
	if gUser.ID == "" || gUser.Email == "" {
		return "", ErrEmptyInput
	}
	if _, err := mail.ParseAddress(gUser.Email); err != nil {
		return "", ErrInvalidEmail
	}

	tx, err := a.Conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("%w: could not start google login transaction: %v", ErrDatabaseUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var authProvider sql.NullString
	var googleID sql.NullString
	err = tx.QueryRow(
		ctx,
		"SELECT auth_provider, google_id FROM users WHERE user_id = $1",
		gUser.Email,
	).Scan(&authProvider, &googleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = tx.Exec(
				ctx,
				"INSERT INTO users (user_id, password_hash, salt, auth_provider, google_id) VALUES ($1, NULL, NULL, 'google', $2)",
				gUser.Email,
				gUser.ID,
			)
			if err != nil {
				return "", fmt.Errorf("%w: failed to create google user: %v", ErrDatabaseUnavailable, err)
			}
		} else {
			return "", fmt.Errorf("%w: failed to query existing user: %v", ErrDatabaseUnavailable, err)
		}
	} else {
		if googleID.Valid && googleID.String != "" && googleID.String != gUser.ID {
			return "", fmt.Errorf("%w: google account mismatch for user", ErrInvalidCredentials)
		}
		if !googleID.Valid || googleID.String == "" {
			_, err = tx.Exec(
				ctx,
				"UPDATE users SET google_id = $1, auth_provider = CASE WHEN auth_provider = 'local' THEN auth_provider ELSE 'google' END WHERE user_id = $2",
				gUser.ID,
				gUser.Email,
			)
			if err != nil {
				return "", fmt.Errorf("%w: failed to link google account: %v", ErrDatabaseUnavailable, err)
			}
		}
		if authProvider.Valid && authProvider.String == "" {
			_, err = tx.Exec(ctx, "UPDATE users SET auth_provider = 'google' WHERE user_id = $1", gUser.Email)
			if err != nil {
				return "", fmt.Errorf("%w: failed to update auth provider: %v", ErrDatabaseUnavailable, err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("%w: failed to finalize google login: %v", ErrDatabaseUnavailable, err)
	}

	token, err := a.GenerateToken(gUser.Email)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (a *Auth) RegisterUser(username, password string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	salt, err := generateSalt(32)
	if err != nil {
		return err
	}

	hash := a.HashPassword(password, salt)

	_, err = a.Conn.Exec(context.Background(),
		"INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)",
		username, hash, salt,
	)
	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) ChangePass(username, newPassword string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	newSalt, err := generateSalt(32)
	if err != nil {
		return fmt.Errorf("%w: could not generate new salt: %v", ErrInvalidInput, err)
	}

	newHash := a.HashPassword(newPassword, newSalt)

	cmdTag, err := a.Conn.Exec(context.Background(),
		"UPDATE users SET password_hash = $1, salt = $2 WHERE user_id = $3",
		newHash, newSalt, username,
	)
	if err != nil {
		return fmt.Errorf("%w: database error while updating password: %v", ErrDatabaseUnavailable, err)
	}

	if cmdTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (a *Auth) DeleteUser(username string) error {
	if a.Conn == nil {
		return ErrNotInitialized
	}

	_, err := a.Conn.Exec(
		context.Background(),
		"DELETE FROM users WHERE user_id = $1",
		username,
	)

	if err != nil {
		return err
	}
	return nil
}

type User struct {
	UserID string `json:"user_id"`
}

func (a *Auth) UserExists(userEmail string) (bool, error) {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return false, ErrInvalidEmail
	}
	if a.Conn == nil {
		return false, ErrDatabaseUnavailable
	}

	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)"
	err := a.Conn.QueryRow(context.Background(), query, userEmail).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	return exists, nil
}

func (a *Auth) ListUsers(limit, offset int) ([]User, error) {
	if a.Conn == nil {
		return nil, ErrDatabaseUnavailable
	}

	query := "SELECT user_id FROM users LIMIT $1 OFFSET $2"
	rows, err := a.Conn.Query(context.Background(), query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UserID); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return users, nil
}
