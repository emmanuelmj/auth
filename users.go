package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"unicode"
)

/* generateSalt generates a cryptographic salt of the specified size. */
func generateSalt(size int) (string, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), nil
}

/* validatePassword checks if a password meets the configured PasswordPolicy. */
func (a *Auth) validatePassword(password string) error {
	if len(password) < a.passwordPolicy.MinLength {
		return fmt.Errorf("password must be at least %d characters", a.passwordPolicy.MinLength)
	}
	if len(password) > a.passwordPolicy.MaxLength {
		return fmt.Errorf("password cannot exceed %d characters", a.passwordPolicy.MaxLength)
	}

	if a.passwordPolicy.RequireUppercase || a.passwordPolicy.RequireNumber || a.passwordPolicy.RequireSpecial {
		var hasUpper, hasNumber, hasSpecial bool
		for _, char := range password {
			switch {
			case unicode.IsUpper(char):
				hasUpper = true
			case unicode.IsNumber(char):
				hasNumber = true
			case unicode.IsPunct(char) || unicode.IsSymbol(char):
				hasSpecial = true
			}
		}

		if a.passwordPolicy.RequireUppercase && !hasUpper {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
		if a.passwordPolicy.RequireNumber && !hasNumber {
			return fmt.Errorf("password must contain at least one number")
		}
		if a.passwordPolicy.RequireSpecial && !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

/* LoginUser attempts to log a user in using their username and password. */
func (a *Auth) LoginUser(ctx context.Context, username, password string) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	storedHash, storedSalt, err := a.storage.GetUserHashAndSalt(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrUserNotFound
		}
		return ErrDatabaseUnavailable
	}

	if storedHash == "OAUTH_MANAGED" {
		return ErrInvalidCredentials
	}

	if !a.comparePasswords(password, storedSalt, storedHash) {
		return ErrInvalidCredentials
	}

	return nil
}

/*
LoginJWT validates a token string by calling auth.ValidateToken (JWT login).
This is the recommended way to validate a user's JWT.
It returns the claims if the token is valid.
*/
func (a *Auth) LoginJWT(ctx context.Context, tokenString string) (*JWTClaims, error) {
	return a.ValidateToken(ctx, tokenString)
}

/* RegisterUser creates a new user with the given username and password. */
func (a *Auth) RegisterUser(ctx context.Context, username, password string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.validatePassword(password); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	salt, err := generateSalt(32)
	if err != nil {
		return err
	}

	hash, err := a.HashPassword(password, salt)
	if err != nil {
		return err
	}

	if err := a.storage.InsertUser(ctx, username, hash, salt); err != nil {
		return err
	}

	return nil
}

/* ChangePass changes a user's password to a new one. */
func (a *Auth) ChangePass(ctx context.Context, username, newPassword string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.validatePassword(newPassword); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	newSalt, err := generateSalt(32)
	if err != nil {
		return fmt.Errorf("%w: could not generate new salt: %v", ErrInvalidInput, err)
	}

	newHash, err := a.HashPassword(newPassword, newSalt)
	if err != nil {
		return fmt.Errorf("%w: could not hash new password: %v", ErrInvalidInput, err)
	}

	rowsAffected, err := a.storage.UpdateUserPassword(ctx, username, newHash, newSalt)
	if err != nil {
		return fmt.Errorf("%w: database error while updating password: %v", ErrDatabaseUnavailable, err)
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

/* DeleteUser completely removes a user and their associated data from the system. */
func (a *Auth) DeleteUser(ctx context.Context, username string) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	if err := a.storage.DeleteUser(ctx, username); err != nil {
		return fmt.Errorf("%w: database error while deleting user: %v", ErrDatabaseUnavailable, err)
	}

	return nil
}

/* UserExists checks if a user with the given username exists in the system. */
func (a *Auth) UserExists(ctx context.Context, userEmail string) (bool, error) {
	if a.storage == nil {
		return false, ErrDatabaseUnavailable
	}

	exists, err := a.storage.UserExists(ctx, userEmail)
	if err != nil {
		return false, fmt.Errorf("%w: database error while checking user existence: %v", ErrDatabaseUnavailable, err)
	}

	return exists, nil
}

/* User contains basic information about a user in the system. */
type User struct {
	UserID string `json:"user_id"`
}

/* ListUsers returns a paginated list of users. */
func (a *Auth) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	if a.storage == nil {
		return nil, ErrDatabaseUnavailable
	}

	users, err := a.storage.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return users, nil
}

/*
upsertOAuthUser safely inserts an OAuth user into the database without a real password.
Uses placeholder values for password_hash and salt to maintain NOT NULL constraints.
*/
func (a *Auth) upsertOAuthUser(ctx context.Context, email string) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	if _, err := mail.ParseAddress(email); err != nil {
		return ErrInvalidEmail
	}

	if err := a.storage.UpsertOAuthUser(ctx, email); err != nil {
		return fmt.Errorf("failed to upsert oauth user: %w", err)
	}

	return nil
}
