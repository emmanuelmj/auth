package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

type registrationEmailCapture struct {
	code string
}

func (c *registrationEmailCapture) SendEmail(_ context.Context, _ string, _ string, body string) error {
	prefix := "Your registration verification code is: "
	if !strings.Contains(body, prefix) {
		prefix = "Your OTP is: "
	}
	firstLine := strings.SplitN(body, "\n", 2)[0]
	c.code = strings.TrimPrefix(firstLine, prefix)
	if c.code == firstLine {
		return errors.New("registration code missing from email body")
	}
	return nil
}

func setupEmailRegistrationAuth(t *testing.T, sender *registrationEmailCapture) *auth.Auth {
	t.Helper()
	return setupTestAuth(t,
		auth.WithOTP(6, 5*time.Minute),
		auth.WithEmailSender(sender),
	)
}

func TestIntegrationEmailRegistrationCreatesAccountOnlyAfterCorrectOTP(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-success@example.com"
	const password = "StrongP@ssword123!"

	if err := a.StartEmailRegistration(ctx, email, password); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}
	db := getTestDBPool(t, ctx)
	var userExists bool
	if err := db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)", email).Scan(&userExists); err != nil {
		t.Fatalf("failed to check pre-verification account: %v", err)
	}
	if userExists {
		t.Fatal("account was created before email verification")
	}
	var pendingHash, pendingSalt string
	if err := db.QueryRow(ctx, "SELECT password_hash, salt FROM pending_email_registrations WHERE user_id = $1", email).Scan(&pendingHash, &pendingSalt); err != nil {
		t.Fatalf("failed to load pending registration: %v", err)
	}
	if pendingHash == password || pendingSalt == password {
		t.Fatal("pending registration stored the plaintext password")
	}
	if sender.code == "" {
		t.Fatal("registration email did not contain an OTP")
	}

	if err := a.CompleteEmailRegistration(ctx, email, sender.code); err != nil {
		t.Fatalf("failed to complete registration: %v", err)
	}
	var emailVerified bool
	if err := db.QueryRow(ctx, "SELECT email_verified FROM users WHERE user_id = $1", email).Scan(&emailVerified); err != nil {
		t.Fatalf("failed to read verified user: %v", err)
	}
	if !emailVerified {
		t.Fatal("completed registration was not marked email-verified")
	}
	if err := a.LoginUser(ctx, email, password); err != nil {
		t.Fatalf("verified user could not log in: %v", err)
	}
	if exists, err := a.UserExists(ctx, email); err != nil || !exists {
		t.Fatalf("verified user should exist, exists=%t err=%v", exists, err)
	}
}

func TestIntegrationPendingRegistrationExpiryIsTimezoneSafe(t *testing.T) {
	skipIfShort(t)
	previousLocal := time.Local
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatalf("failed to load non-UTC test timezone: %v", err)
	}
	time.Local = loc
	t.Cleanup(func() { time.Local = previousLocal })

	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-timezone@example.com"

	startedAt := time.Now().UTC()
	if err := a.StartEmailRegistration(ctx, email, "StrongP@ssword123!"); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}
	var expiresAt time.Time
	var dataType string
	db := getTestDBPool(t, ctx)
	if err := db.QueryRow(ctx, `
		SELECT expires_at,
		       (SELECT data_type FROM information_schema.columns
		        WHERE table_schema = current_schema()
		          AND table_name = 'pending_email_registrations'
		          AND column_name = 'expires_at')
		FROM pending_email_registrations WHERE user_id = $1`, email).Scan(&expiresAt, &dataType); err != nil {
		t.Fatalf("failed to load pending expiry: %v", err)
	}
	if dataType != "timestamp with time zone" {
		t.Fatalf("expected TIMESTAMPTZ expiry, got %q", dataType)
	}
	if expiresAt.UTC().Before(startedAt.Add(4*time.Minute)) || expiresAt.UTC().After(time.Now().UTC().Add(6*time.Minute)) {
		t.Fatalf("pending expiry is not the expected UTC instant: got %s", expiresAt.UTC())
	}
	if _, err := db.Exec(ctx, "UPDATE pending_email_registrations SET expires_at = $1 WHERE user_id = $2", time.Now().UTC().Add(-time.Minute), email); err != nil {
		t.Fatalf("failed to set expired pending registration: %v", err)
	}
	if err := a.CompleteEmailRegistration(ctx, email, sender.code); !errors.Is(err, auth.ErrOTPExpired) {
		t.Fatalf("expected expired OTP after UTC expiry comparison, got %v", err)
	}
}

func TestIntegrationEmailRegistrationRejectsWrongOTP(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-wrong@example.com"

	if err := a.StartEmailRegistration(ctx, email, "StrongP@ssword123!"); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}
	if err := a.CompleteEmailRegistration(ctx, email, "000000"); !errors.Is(err, auth.ErrInvalidOTP) {
		t.Fatalf("expected incorrect OTP error, got %v", err)
	}
	var exists bool
	if err := getTestDBPool(t, ctx).QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)", email).Scan(&exists); err != nil {
		t.Fatalf("failed to check user: %v", err)
	}
	if exists {
		t.Fatal("incorrect OTP created an account")
	}
}

func TestIntegrationEmailRegistrationRejectsExpiredOTP(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-expired@example.com"

	if err := a.StartEmailRegistration(ctx, email, "StrongP@ssword123!"); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}
	if _, err := getTestDBPool(t, ctx).Exec(ctx, "UPDATE pending_email_registrations SET expires_at = $1 WHERE user_id = $2", time.Now().UTC().Add(-time.Minute), email); err != nil {
		t.Fatalf("failed to expire pending OTP: %v", err)
	}
	if err := a.CompleteEmailRegistration(ctx, email, sender.code); !errors.Is(err, auth.ErrOTPExpired) {
		t.Fatalf("expected expired OTP error, got %v", err)
	}
}

func TestIntegrationEmailRegistrationOTPIsSingleUseAndDuplicateIsRejected(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-replay@example.com"

	if err := a.StartEmailRegistration(ctx, email, "StrongP@ssword123!"); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}
	code := sender.code
	if err := a.CompleteEmailRegistration(ctx, email, code); err != nil {
		t.Fatalf("failed to complete registration: %v", err)
	}
	if err := a.CompleteEmailRegistration(ctx, email, code); !errors.Is(err, auth.ErrInvalidOTP) {
		t.Fatalf("expected replayed OTP to be rejected, got %v", err)
	}
	if err := a.StartEmailRegistration(ctx, email, "AnotherS@fePassword123!"); !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("expected duplicate registration to be rejected, got %v", err)
	}
}

func TestIntegrationConcurrentEmailRegistrationCompletionIsSingleUse(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "verify-concurrent@example.com"
	if err := a.StartEmailRegistration(ctx, email, "StrongP@ssword123!"); err != nil {
		t.Fatalf("failed to start registration: %v", err)
	}

	start := make(chan struct{})
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errCh <- a.CompleteEmailRegistration(ctx, email, sender.code)
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	successes := 0
	replays := 0
	for err := range errCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, auth.ErrInvalidOTP):
			replays++
		default:
			t.Fatalf("unexpected concurrent completion error: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("expected one completion and one rejected replay, successes=%d replays=%d", successes, replays)
	}
}

func TestIntegrationExistingAccountCanBeVerifiedWithOTP(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "legacy-unverified@example.com"
	const password = "LegacyAccountPassword1!"
	db := getTestDBPool(t, ctx)
	salt := "legacy-test-salt"
	hash, err := a.HashPassword(password, salt)
	if err != nil {
		t.Fatalf("failed to hash legacy test password: %v", err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", email, hash, salt); err != nil {
		t.Fatalf("failed to create existing local account: %v", err)
	}

	if err := a.SendOTP(ctx, email); err != nil {
		t.Fatalf("failed to send verification OTP: %v", err)
	}
	if sender.code == "" {
		t.Fatal("verification email did not contain an OTP")
	}
	if err := a.VerifyExistingEmail(ctx, email, password, sender.code); err != nil {
		t.Fatalf("failed to verify existing account: %v", err)
	}
	var verified bool
	if err := db.QueryRow(ctx, "SELECT email_verified FROM users WHERE user_id = $1", email).Scan(&verified); err != nil {
		t.Fatalf("failed to read verification status: %v", err)
	}
	if !verified {
		t.Fatal("existing account was not marked verified")
	}
}

func TestIntegrationExistingAccountVerificationRejectsWrongPassword(t *testing.T) {
	skipIfShort(t)
	sender := &registrationEmailCapture{}
	a := setupEmailRegistrationAuth(t, sender)
	ctx := context.Background()
	const email = "legacy-wrong-password@example.com"
	const password = "LegacyAccountPassword1!"
	db := getTestDBPool(t, ctx)
	salt := "legacy-test-salt"
	hash, err := a.HashPassword(password, salt)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", email, hash, salt); err != nil {
		t.Fatalf("failed to create existing local account: %v", err)
	}
	if err := a.SendOTP(ctx, email); err != nil {
		t.Fatalf("failed to send verification OTP: %v", err)
	}
	if err := a.VerifyExistingEmail(ctx, email, "wrong-password", sender.code); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected incorrect local password to be rejected, got %v", err)
	}
	var verified bool
	if err := db.QueryRow(ctx, "SELECT email_verified FROM users WHERE user_id = $1", email).Scan(&verified); err != nil {
		t.Fatalf("failed to read verification status: %v", err)
	}
	if verified {
		t.Fatal("incorrect local password promoted the account")
	}
}

func TestIntegrationSchemaUpgradeLeavesExistingUsersUnverified(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t,
		auth.WithOAuth("test-client-id", "test-client-secret", "http://localhost/callback"),
		auth.WithJWT([]byte("migration-test-signing-secret"), time.Hour),
	)
	ctx := context.Background()
	db := getTestDBPool(t, ctx)
	const email = "legacy-schema-user@example.com"
	const hash = "preserved-password-hash"
	const salt = "preserved-password-salt"
	if _, err := db.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", email, hash, salt); err != nil {
		t.Fatalf("failed to insert legacy user: %v", err)
	}
	const googleEmail = "legacy-google-managed@example.com"
	if _, err := db.Exec(ctx, "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", googleEmail, "OAUTH_MANAGED", "OAUTH_MANAGED_SALT_16B"); err != nil {
		t.Fatalf("failed to insert legacy Google-managed user: %v", err)
	}
	if _, err := db.Exec(ctx, "ALTER TABLE users DROP COLUMN email_verified"); err != nil {
		t.Fatalf("failed to simulate pre-migration schema: %v", err)
	}

	storage, err := auth.NewPostgresStorage(ctx, testDBPort, testDBUser, testDBPass, testDBName, testDBHost)
	if err != nil {
		t.Fatalf("failed to open storage for schema upgrade: %v", err)
	}
	defer storage.Close()
	if err := storage.CheckTables(ctx); err != nil {
		t.Fatalf("failed to upgrade existing schema: %v", err)
	}
	if err := storage.CheckTables(ctx); err != nil {
		t.Fatalf("repeated schema upgrade failed: %v", err)
	}

	var verified bool
	var storedHash, storedSalt string
	if err := db.QueryRow(ctx, "SELECT email_verified, password_hash, salt FROM users WHERE user_id = $1", email).Scan(&verified, &storedHash, &storedSalt); err != nil {
		t.Fatalf("failed to read migrated user: %v", err)
	}
	if verified {
		t.Fatal("schema upgrade must not automatically verify existing accounts")
	}
	if storedHash != hash || storedSalt != salt {
		t.Fatal("schema upgrade changed existing credentials")
	}
	var googleVerified bool
	var googleHash, googleSalt string
	if err := db.QueryRow(ctx, "SELECT email_verified, password_hash, salt FROM users WHERE user_id = $1", googleEmail).Scan(&googleVerified, &googleHash, &googleSalt); err != nil {
		t.Fatalf("failed to read migrated Google-managed user: %v", err)
	}
	if !googleVerified {
		t.Fatal("legacy Google-managed account was not marked verified")
	}
	if googleHash != "OAUTH_MANAGED" || googleSalt != "OAUTH_MANAGED_SALT_16B" {
		t.Fatal("schema upgrade changed legacy Google-managed credentials")
	}
	jwt, err := a.HandleGoogleCallback(newGoogleCallbackContext(googleEmail, true), "test-code")
	if err != nil || jwt == "" {
		t.Fatalf("migrated Google-managed account could not sign in: jwt=%q err=%v", jwt, err)
	}
}
