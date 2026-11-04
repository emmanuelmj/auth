package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
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

	if storedHash == OAuthManagedHash {
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

/* RegisterUser creates a non-email user. Email usernames must use the verification flow. */
func (a *Auth) RegisterUser(ctx context.Context, username, password string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}
	if strings.Contains(username, "@") {
		return ErrEmailVerificationRequired
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

// StartEmailRegistration stores only a password hash and salt, then emails a
// short-lived OTP. The user account is not created until CompleteEmailRegistration
// successfully verifies that code.
func (a *Auth) StartEmailRegistration(ctx context.Context, email, password string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}
	if err := validateRegistrationEmail(email); err != nil {
		return err
	}
	if !a.otpEnabled || a.otpExpiry <= 0 || len(a.pepper) == 0 {
		return fmt.Errorf("%w: email registration requires WithPepper and WithOTP", ErrInvalidInput)
	}
	if a.emailSender == nil {
		return ErrSMTPNotInitialized
	}
	if err := a.validatePassword(password); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	exists, err := a.storage.UserExists(ctx, email)
	if err != nil {
		return fmt.Errorf("%w: could not check user existence: %v", ErrDatabaseUnavailable, err)
	}
	if exists {
		return ErrUserAlreadyExists
	}
	storage, ok := a.storage.(EmailVerificationStorage)
	if !ok {
		return fmt.Errorf("%w: storage does not support email registration", ErrDatabaseUnavailable)
	}
	code, err := a.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate registration OTP: %w", err)
	}
	salt, err := generateSalt(32)
	if err != nil {
		return err
	}
	hash, err := a.HashPassword(password, salt)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(a.otpExpiry)
	if err := storage.CreatePendingEmailRegistration(ctx, email, hash, salt, a.computeOTPHash(code), expiresAt); err != nil {
		return fmt.Errorf("%w: could not save pending registration: %v", ErrDatabaseUnavailable, err)
	}
	minutes := int(a.otpExpiry.Minutes())
	body := fmt.Sprintf("Your registration verification code is: %s\n\nValid for %d minutes.", code, minutes)
	if err := a.emailSender.SendEmail(ctx, email, "Verify your email address", body); err != nil {
		return fmt.Errorf("failed to send registration verification email: %w", err)
	}
	return nil
}

// CompleteEmailRegistration creates a verified account only after the OTP
// associated with its pending registration has been checked and consumed.
func (a *Auth) CompleteEmailRegistration(ctx context.Context, email, code string) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}
	if err := validateRegistrationEmail(email); err != nil {
		return err
	}
	if code == "" {
		return ErrEmptyInput
	}
	storage, ok := a.storage.(EmailVerificationStorage)
	if !ok {
		return fmt.Errorf("%w: storage does not support email registration", ErrDatabaseUnavailable)
	}
	if err := storage.CompletePendingEmailRegistration(ctx, email, a.computeOTPHash(code), time.Now()); err != nil {
		return err
	}
	return nil
}

// VerifyExistingEmail marks an existing local account verified after the caller
// proves the local password and supplies an OTP sent with SendOTP. Verification
// and OTP consumption happen atomically in storage.
func (a *Auth) VerifyExistingEmail(ctx context.Context, email, password, code string) error {
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}
	if err := validateRegistrationEmail(email); err != nil {
		return err
	}
	if err := a.LoginUser(ctx, email, password); err != nil {
		return err
	}
	if code == "" {
		return ErrEmptyInput
	}
	storage, ok := a.storage.(EmailVerificationStorage)
	if !ok {
		return fmt.Errorf("%w: storage does not support email verification", ErrDatabaseUnavailable)
	}
	if err := storage.VerifyExistingEmailOTP(ctx, email, a.computeOTPHash(code), time.Now()); err != nil {
		return err
	}
	return nil
}

func validateRegistrationEmail(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return ErrInvalidEmail
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
		return ErrNotInitialized
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

	if _, err := mail.ParseAddress(userEmail); err != nil {
		return false, ErrInvalidEmail
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
func (a *Auth) upsertOAuthUser(ctx context.Context, email string) (bool, error) {
	if a.storage == nil {
		return false, ErrDatabaseUnavailable
	}

	if err := validateRegistrationEmail(email); err != nil {
		return false, err
	}
	storage, ok := a.storage.(OAuthAccountStorage)
	if !ok {
		return false, fmt.Errorf("%w: storage does not support secure OAuth account linking", ErrDatabaseUnavailable)
	}
	linked, err := storage.UpsertVerifiedOAuthUser(ctx, email)
	if err != nil {
		return false, fmt.Errorf("failed to upsert verified OAuth user: %w", err)
	}
	return linked, nil
}
