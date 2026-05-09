package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/mail"
	"time"

	"github.com/GCET-Open-Source-Foundation/auth/email"
)

/* OTPInit configures the OTP settings. If values are 0, defaults are used. */
func (a *Auth) OTPInit(ctx context.Context, length int, expiry time.Duration) error {
	if length < 4 || length > 10 {
		return fmt.Errorf("%w: length %d (must be between 4 and 10)", ErrInvalidInput, length)
	}
	if expiry <= 0 {
		return fmt.Errorf("%w: expiry %v", ErrInvalidInput, expiry)
	}

	a.otpLength = length
	a.otpExpiry = expiry
	return nil
}

/* Helper: Generates a secure random number based on the configured OTP length */
func (a *Auth) generateOTP() (string, error) {
	/* 1. Validation Guard */
	if a.otpLength < 4 || a.otpLength > 10 {
		return "", fmt.Errorf("%w: length %d (must be between 4 and 10)", ErrInvalidInput, a.otpLength)
	}

	/* 2. Calculate the max value (e.g., 10^6 = 1,000,000)*/
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(a.otpLength)), nil)

	/* 3. Generate secure random number */
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	/* 4. Dynamically pad the string (e.g., 6 digits becomes %06d) */
	return fmt.Sprintf("%0*d", a.otpLength, n), nil
}

/*
SendOTP generates an OTP, saves it to the DB (upsert), and emails it.
Usage: auth.SendOTP("user@example.com")
*/
func (a *Auth) SendOTP(ctx context.Context, userEmail string) error {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return ErrInvalidEmail
	}
	if a.storage == nil {
		return ErrNotInitialized
	}
	if a.smtpHost == "" {
		return ErrSMTPNotInitialized
	}

	/* 1. Generate Code */
	code, err := a.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	/* 2. Set Expiry (Uses the config field instead of hardcoded value) */
	if a.otpExpiry <= 0 {
		return fmt.Errorf("%w: duration %v", ErrInvalidInput, a.otpExpiry)
	}
	expiry := time.Now().Add(a.otpExpiry)
	
	/* 3. Upsert into DB */
	if err := a.storage.InsertOTP(ctx, userEmail, code, expiry); err != nil {
		return fmt.Errorf("db error saving OTP: %w", err)
	}

	/* 4. Send Email */
	subject := "Your Verification Code"
	/* Format to '5 minutes' instead of '5m0s' */
	minutes := int(a.otpExpiry.Minutes())
	body := fmt.Sprintf("Your OTP is: %s\n\nValid for %d minutes.", code, minutes)
	err = email.Send(
		a.smtpHost, a.smtpPort,
		a.smtpEmail, string(a.smtpPassword),
		userEmail, subject, body,
	)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

/*
VerifyOTP checks if the code is correct and not expired.
If valid, it deletes the OTP to prevent reuse.
*/
func (a *Auth) VerifyOTP(ctx context.Context, userEmail, inputCode string) error {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return ErrInvalidEmail
	}
	if a.storage == nil {
		return ErrDatabaseUnavailable
	}

	/* Get the OTP */
	storedCode, expiry, err := a.storage.GetOTP(ctx, userEmail)
	if err != nil {
		return ErrInvalidOTP /* OTP not found */
	}

	/* Check match and expiry */
	if storedCode != inputCode {
		return ErrInvalidOTP
	}
	if time.Now().After(expiry) {
		return ErrOTPExpired
	}

	/* Valid! Delete it. */
	_ = a.storage.DeleteOTP(ctx, userEmail)
	return nil
}

/*
startOTPCleanup is an internal function that runs in the background.
It periodically deletes expired OTPs from the database.
The cleanup cycle is fixed (5 minutes) to ensure consistent performance
regardless of the configured OTP expiration duration.
*/
func (a *Auth) startOTPCleanup() {
	/* Fixed 5-minute interval to prevent DB stress */
	ticker := time.NewTicker(5 * time.Minute)

	go func() {
		/* Ensure the ticker stops when we exit to prevent leaks */
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				/* The Timer ticked: Do the work */
				if a.storage != nil {
					_ = a.storage.CleanupExpiredOTPs(a.ctx)
				}

			case <-a.ctx.Done():
				/* The Context was cancelled: STOP EVERYTHING */
				/* This returns from the function, killing the goroutine "neatly" */
				return
			}
		}
	}()
}

func (a *Auth) OTPExists(ctx context.Context, userEmail string) (bool, error) {
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return false, ErrInvalidEmail
	}
	if a.storage == nil {
		return false, ErrDatabaseUnavailable
	}

	_, expiry, err := a.storage.GetOTP(ctx, userEmail)
	if err != nil {
		/* if error, it means it doesn't exist or other db error */
		return false, nil
	}

	if time.Now().After(expiry) {
		return false, nil
	}

	return true, nil
}

func (a *Auth) ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error) {
	if a.storage == nil {
		return nil, ErrDatabaseUnavailable
	}

	emails, err := a.storage.ListActiveOTPs(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseUnavailable, err)
	}

	return emails, nil
}
