package tests

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

func getTestDBPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		testDBUser, testDBPass, testDBHost, testDBPort, testDBName)
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("getTestDBPool: failed to connect: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
	})
	return pool
}

func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
}

/* ======================== Init Integration ======================== */

/*
TestIntegrationInit verifies that Init successfully connects to a real database
and creates all required tables.
*/
func TestIntegrationInit(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	if !a.HasStorage() {
		t.Fatal("expected non-nil database connection")
	}
}

/* ======================== User Registration & Login ======================== */

/*
TestIntegrationRegisterAndLogin tests the full user lifecycle:
register -> login -> wrong password -> non-existent user -> delete -> post-delete.
*/
func TestIntegrationRegisterAndLogin(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	err := a.RegisterUser(context.Background(), "alice@example.com", "StrongP@ssw0rd1")
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}

	err = a.LoginUser(context.Background(), "alice@example.com", "StrongP@ssw0rd1")
	if err != nil {
		t.Errorf("expected successful login, got: %v", err)
	}

	err = a.LoginUser(context.Background(), "alice@example.com", "wrongpassword")
	if err == nil {
		t.Error("expected error for wrong password")
	}

	err = a.LoginUser(context.Background(), "nobody@example.com", "password")
	if err == nil {
		t.Error("expected error for non-existent user")
	}

	err = a.DeleteUser(context.Background(), "alice@example.com")
	if err != nil {
		t.Errorf("failed to delete user: %v", err)
	}

	err = a.LoginUser(context.Background(), "alice@example.com", "StrongP@ssw0rd1")
	if err == nil {
		t.Error("expected error logging in after deletion")
	}
}

/*
TestIntegrationUserExists verifies the UserExists check against a real database.
*/
func TestIntegrationUserExists(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "check@example.com", "P@ssword123!")

	exists, err := a.UserExists(context.Background(), "check@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}

	exists, err = a.UserExists(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected user not to exist")
	}
}

/*
TestIntegrationListUsers verifies pagination of users.
*/
func TestIntegrationListUsers(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	_ = a.RegisterUser(context.Background(), "list1@example.com", "TestP@ss0001!")
	_ = a.RegisterUser(context.Background(), "list2@example.com", "TestP@ss0002!")
	_ = a.RegisterUser(context.Background(), "list3@example.com", "TestP@ss0003!")

	users, err := a.ListUsers(context.Background(), 2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) < 2 {
		t.Errorf("expected at least 2 users, got %d", len(users))
	}

	users, err = a.ListUsers(context.Background(), 10, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) < 1 {
		t.Errorf("expected at least 1 user on second page, got %d", len(users))
	}
}

/*
TestIntegrationChangePassword verifies that password changes work end-to-end.
*/
func TestIntegrationChangePassword(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "changeme@example.com", "OldP@ssword1!")

	err := a.ChangePass(context.Background(), "changeme@example.com", "NewP@ssword1!")
	if err != nil {
		t.Fatalf("failed to change password: %v", err)
	}

	err = a.LoginUser(context.Background(), "changeme@example.com", "OldP@ssword1!")
	if err == nil {
		t.Error("expected old password to fail after change")
	}

	err = a.LoginUser(context.Background(), "changeme@example.com", "NewP@ssword1!")
	if err != nil {
		t.Errorf("expected new password to succeed: %v", err)
	}
}

/*
TestIntegrationChangePassNonExistent verifies that changing a ghost user's password fails.
*/
func TestIntegrationChangePassNonExistent(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	err := a.ChangePass(context.Background(), "ghost@example.com", "NewP@ss12345!")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got: %v", err)
	}
}

/*
TestIntegrationDuplicateRegistration verifies PK constraint on duplicate user.
*/
func TestIntegrationDuplicateRegistration(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	err := a.RegisterUser(context.Background(), "dupe@example.com", "P@ssword1234!")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	err = a.RegisterUser(context.Background(), "dupe@example.com", "P@ssword5678!")
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

/* ======================== User + JWT Combined ======================== */

/*
TestIntegrationRegisterLoginJWT tests:
register -> login with password -> generate JWT -> validate -> LoginJWT.
*/
func TestIntegrationRegisterLoginJWT(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithJWT([]byte("integration-test-secret"), 24*time.Hour))
	_ = a.RegisterUser(context.Background(), "jwtuser@example.com", "S3cureP@ss12!")

	err := a.LoginUser(context.Background(), "jwtuser@example.com", "S3cureP@ss12!")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	token, err := a.GenerateToken(context.Background(), "jwtuser@example.com")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := a.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if claims.UserID != "jwtuser@example.com" {
		t.Errorf("expected 'jwtuser@example.com', got '%s'", claims.UserID)
	}

	claims2, err := a.LoginJWT(context.Background(), token)
	if err != nil {
		t.Fatalf("LoginJWT failed: %v", err)
	}
	if claims2.UserID != "jwtuser@example.com" {
		t.Errorf("expected 'jwtuser@example.com', got '%s'", claims2.UserID)
	}
}

/* ======================== User + Pepper ======================== */

/*
TestIntegrationPepperRegistration verifies peppered registration round-trip.
*/
func TestIntegrationPepperRegistration(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithPepper([]byte("test-pepper-value")))
	_ = a.RegisterUser(context.Background(), "peppered@example.com", "MyP@ssword12!")

	err := a.LoginUser(context.Background(), "peppered@example.com", "MyP@ssword12!")
	if err != nil {
		t.Errorf("login with pepper should succeed: %v", err)
	}
}

/* ======================== Spaces, Roles, Permissions ======================== */

/*
TestIntegrationSpacesRolesPermissions tests the complete RBAC lifecycle.
*/
func TestIntegrationSpacesRolesPermissions(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	err := a.CreateSpace(context.Background(), "workspace-alpha", 1)
	if err != nil {
		t.Fatalf("failed to create space: %v", err)
	}

	err = a.CreateRole(context.Background(), "admin")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	_ = a.RegisterUser(context.Background(), "rbac@example.com", "TestP@ssword1!")

	err = a.CreatePermissions(context.Background(), "rbac@example.com", "workspace-alpha", "admin")
	if err != nil {
		t.Fatalf("failed to assign permission: %v", err)
	}

	err = a.CheckPermissions(context.Background(), "rbac@example.com", "workspace-alpha", "admin")
	if err != nil {
		t.Errorf("expected permission to exist: %v", err)
	}

	err = a.CheckPermissions(context.Background(), "rbac@example.com", "workspace-alpha", "viewer")
	if err == nil {
		t.Error("expected error for non-existent permission")
	}

	_ = a.DeletePermission(context.Background(), "rbac@example.com", "workspace-alpha", "admin")

	err = a.CheckPermissions(context.Background(), "rbac@example.com", "workspace-alpha", "admin")
	if err == nil {
		t.Error("expected error after deleting permission")
	}

	_ = a.DeleteRole(context.Background(), "admin")
	_ = a.DeleteSpace(context.Background(), "workspace-alpha")
}

/*
TestIntegrationCascadeDeleteUser verifies FK ON DELETE CASCADE for permissions.
*/
func TestIntegrationCascadeDeleteUser(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	_ = a.CreateSpace(context.Background(), "cascade-space", 1)
	_ = a.CreateRole(context.Background(), "editor")
	_ = a.RegisterUser(context.Background(), "cascade@example.com", "TestP@ssword1!")
	_ = a.CreatePermissions(context.Background(), "cascade@example.com", "cascade-space", "editor")

	err := a.CheckPermissions(context.Background(), "cascade@example.com", "cascade-space", "editor")
	if err != nil {
		t.Fatalf("permission should exist before delete: %v", err)
	}

	_ = a.DeleteUser(context.Background(), "cascade@example.com")

	err = a.CheckPermissions(context.Background(), "cascade@example.com", "cascade-space", "editor")
	if err == nil {
		t.Error("expected permission to be cascade-deleted with user")
	}
}

/* ======================== OTP Integration ======================== */

/*
TestIntegrationOTPVerify tests OTP store/verify round-trip.
We bypass SendOTP (needs real SMTP) and insert directly.
*/
func TestIntegrationOTPVerify(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	expiry := time.Now().Add(5 * time.Minute)
	_, err := db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"otp@example.com", computeTestOTPHash("123456"), expiry,
	)
	if err != nil {
		t.Fatalf("failed to insert test OTP: %v", err)
	}

	err = a.VerifyOTP(context.Background(), "otp@example.com", "999999")
	if err == nil {
		t.Error("expected error for wrong OTP code")
	}

	err = a.VerifyOTP(context.Background(), "otp@example.com", "123456")
	if err != nil {
		t.Errorf("expected OTP verification to succeed: %v", err)
	}

	err = a.VerifyOTP(context.Background(), "otp@example.com", "123456")
	if err == nil {
		t.Error("expected error when reusing OTP")
	}
}

/*
TestIntegrationOTPExpired verifies that an expired OTP is rejected.
*/
func TestIntegrationOTPExpired(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	expiry := time.Now().Add(-1 * time.Minute)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"expired@example.com", computeTestOTPHash("654321"), expiry,
	)

	err := a.VerifyOTP(context.Background(), "expired@example.com", "654321")
	if !errors.Is(err, auth.ErrOTPExpired) {
		t.Errorf("expected ErrOTPExpired, got: %v", err)
	}
}

/*
TestIntegrationOTPExists verifies the OTPExists function.
*/
func TestIntegrationOTPExists(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"exists@example.com", computeTestOTPHash("111111"), expiry,
	)

	exists, err := a.OTPExists(context.Background(), "exists@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected OTP to exist")
	}

	exists, err = a.OTPExists(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected OTP not to exist")
	}
}

/*
TestIntegrationListActiveOTPs verifies listing of active OTPs.
*/
func TestIntegrationListActiveOTPs(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"active1@example.com", computeTestOTPHash("111111"), expiry,
	)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"active2@example.com", computeTestOTPHash("222222"), expiry,
	)

	emails, err := a.ListActiveOTPs(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(emails) < 2 {
		t.Errorf("expected at least 2 active OTPs, got %d", len(emails))
	}
}

/* ======================== Refresh Token Integration ======================== */

/*
TestIntegrationRefreshTokenFullCycle tests:
generate -> validate -> rotate -> old revoked -> new valid -> explicit revoke.
*/
func TestIntegrationRefreshTokenFullCycle(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "refresh@example.com", "TestP@ssword1!")

	token, err := a.GenerateRefreshToken(context.Background(), "refresh@example.com")
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty refresh token")
	}
	/* 64 random bytes hex-encoded = 128 character string */
	if len(token) != 128 {
		t.Errorf("expected token length 128 (64 bytes hex), got %d", len(token))
	}

	userID, err := a.ValidateRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("failed to validate refresh token: %v", err)
	}
	if userID != "refresh@example.com" {
		t.Errorf("expected 'refresh@example.com', got '%s'", userID)
	}

	newToken, rotatedUserID, err := a.RotateRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("failed to rotate: %v", err)
	}
	if newToken == "" || newToken == token {
		t.Error("expected a new, different token")
	}
	if rotatedUserID != "refresh@example.com" {
		t.Errorf("expected 'refresh@example.com', got '%s'", rotatedUserID)
	}

	_, err = a.ValidateRefreshToken(context.Background(), token)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected ErrRefreshTokenRevoked for old token, got: %v", err)
	}

	_, err = a.ValidateRefreshToken(context.Background(), newToken)
	if err != nil {
		t.Fatalf("new token should be valid: %v", err)
	}

	_ = a.RevokeRefreshToken(context.Background(), newToken)

	_, err = a.ValidateRefreshToken(context.Background(), newToken)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected ErrRefreshTokenRevoked, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenRevokeAll tests revoking all tokens for a user.
*/
func TestIntegrationRefreshTokenRevokeAll(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "revokeall@example.com", "TestP@ssword1!")

	token1, _ := a.GenerateRefreshToken(context.Background(), "revokeall@example.com")
	token2, _ := a.GenerateRefreshToken(context.Background(), "revokeall@example.com")
	token3, _ := a.GenerateRefreshToken(context.Background(), "revokeall@example.com")

	_ = a.RevokeAllUserRefreshTokens(context.Background(), "revokeall@example.com")

	for _, tok := range []string{token1, token2, token3} {
		_, err := a.ValidateRefreshToken(context.Background(), tok)
		if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
			t.Errorf("expected ErrRefreshTokenRevoked, got: %v", err)
		}
	}
}

/*
TestIntegrationRefreshTokenInvalid verifies that a bogus token is rejected.
*/
func TestIntegrationRefreshTokenInvalid(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	_, err := a.ValidateRefreshToken(context.Background(), "this-token-does-not-exist")
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenCleanup verifies that expired tokens are cleaned up.
*/
func TestIntegrationRefreshTokenCleanup(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())
	_ = a.RegisterUser(context.Background(), "cleanup@example.com", "TestP@ssword1!")

	expiredTime := time.Now().Add(-1 * time.Hour)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO refresh_tokens (token, user_id, expires_at, revoked, created_at) VALUES ($1, $2, $3, false, NOW())",
		"expired-token-abc", "cleanup@example.com", expiredTime,
	)

	_ = a.CleanupExpiredRefreshTokens(context.Background())

	_, err := a.ValidateRefreshToken(context.Background(), "expired-token-abc")
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid after cleanup, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenCascadeDeleteUser verifies FK ON DELETE CASCADE for refresh tokens.
*/
func TestIntegrationRefreshTokenCascadeDeleteUser(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "cascade-rt@example.com", "TestP@ssword1!")

	token, _ := a.GenerateRefreshToken(context.Background(), "cascade-rt@example.com")

	_, err := a.ValidateRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("token should be valid: %v", err)
	}

	_ = a.DeleteUser(context.Background(), "cascade-rt@example.com")

	_, err = a.ValidateRefreshToken(context.Background(), token)
	if !errors.Is(err, auth.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid after user deletion, got: %v", err)
	}
}

/*
TestIntegrationRefreshTokenChainRotation tests 5 sequential rotations:
all old tokens revoked, only the latest valid.
*/
func TestIntegrationRefreshTokenChainRotation(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	_ = a.RegisterUser(context.Background(), "chain@example.com", "TestP@ssword1!")

	token, _ := a.GenerateRefreshToken(context.Background(), "chain@example.com")

	var allOldTokens []string
	for i := 0; i < 5; i++ {
		allOldTokens = append(allOldTokens, token)
		newToken, _, err := a.RotateRefreshToken(context.Background(), token)
		if err != nil {
			t.Fatalf("rotation %d failed: %v", i+1, err)
		}
		token = newToken
	}

	for i, old := range allOldTokens {
		_, err := a.ValidateRefreshToken(context.Background(), old)
		if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
			t.Errorf("old token %d should be revoked, got: %v", i, err)
		}
	}

	userID, err := a.ValidateRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("latest token should be valid: %v", err)
	}
	if userID != "chain@example.com" {
		t.Errorf("expected 'chain@example.com', got '%s'", userID)
	}
}

/* ======================== Combined: JWT + Refresh Token ======================== */

/*
TestIntegrationJWTRefreshTokenFlow tests the complete authentication flow:
register -> login -> JWT + refresh -> validate -> rotate -> new JWT -> validate.
*/
func TestIntegrationJWTRefreshTokenFlow(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithJWT([]byte("jwt-refresh-test-secret"), 24*time.Hour))

	_ = a.RegisterUser(context.Background(), "fullflow@example.com", "MyP@ssword12!")

	err := a.LoginUser(context.Background(), "fullflow@example.com", "MyP@ssword12!")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	accessToken, _ := a.GenerateToken(context.Background(), "fullflow@example.com", 1*time.Hour)
	refreshToken, _ := a.GenerateRefreshToken(context.Background(), "fullflow@example.com")

	claims, err := a.ValidateToken(context.Background(), accessToken)
	if err != nil {
		t.Fatalf("failed to validate access token: %v", err)
	}
	if claims.UserID != "fullflow@example.com" {
		t.Errorf("unexpected UserID: %s", claims.UserID)
	}

	newRefresh, userID, err := a.RotateRefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	newAccess, _ := a.GenerateToken(context.Background(), userID, 1*time.Hour)

	claims, err = a.ValidateToken(context.Background(), newAccess)
	if err != nil {
		t.Fatalf("failed to validate new access token: %v", err)
	}
	if claims.UserID != "fullflow@example.com" {
		t.Errorf("unexpected UserID: %s", claims.UserID)
	}

	_, err = a.ValidateRefreshToken(context.Background(), refreshToken)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("old refresh token should be revoked, got: %v", err)
	}

	_, err = a.ValidateRefreshToken(context.Background(), newRefresh)
	if err != nil {
		t.Errorf("new refresh token should be valid: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + Login ======================== */

/*
TestIntegrationRateLimitedLogin tests rate limiting on login attempts.
*/
func TestIntegrationRateLimitedLogin(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = a.RegisterUser(context.Background(), "limited@example.com", "CorrectP@ss1!")

	userKey := "limited@example.com"

	for i := 0; i < 3; i++ {
		_ = rl.Allow(context.Background(), userKey)
		_ = a.LoginUser(context.Background(), "limited@example.com", "wrongpass")
	}

	err := rl.Allow(context.Background(), userKey)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Errorf("expected ErrRateLimitExceeded, got: %v", err)
	}

	rl.Reset(context.Background(), userKey)

	err = rl.Allow(context.Background(), userKey)
	if err != nil {
		t.Errorf("expected allowed after reset: %v", err)
	}

	err = a.LoginUser(context.Background(), "limited@example.com", "CorrectP@ss1!")
	if err != nil {
		t.Errorf("expected successful login after reset: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + JWT ======================== */

/*
TestIntegrationRateLimitedJWTValidation tests rate limiting on token validation.
*/
func TestIntegrationRateLimitedJWTValidation(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithJWT([]byte("rate-limit-jwt-secret"), 24*time.Hour))

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	clientIP := "192.168.1.100"

	for i := 0; i < 5; i++ {
		_ = rl.Allow(context.Background(), clientIP)
		_, _ = a.ValidateToken(context.Background(), "bogus-token")
	}

	err := rl.Allow(context.Background(), clientIP)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Error("expected rate limit exceeded on 6th request")
	}

	err = rl.Allow(context.Background(), "10.0.0.1")
	if err != nil {
		t.Errorf("different IP should not be rate limited: %v", err)
	}
}

/* ======================== Combined: Password Change + Revoke Tokens ======================== */

/*
TestIntegrationPasswordChangeRevokesTokens tests: change password -> revoke all -> re-login.
*/
func TestIntegrationPasswordChangeRevokesTokens(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithJWT([]byte("pass-change-secret"), 24*time.Hour))

	_ = a.RegisterUser(context.Background(), "secure@example.com", "OldP@ss12345!")

	rt1, _ := a.GenerateRefreshToken(context.Background(), "secure@example.com")
	rt2, _ := a.GenerateRefreshToken(context.Background(), "secure@example.com")

	_ = a.ChangePass(context.Background(), "secure@example.com", "NewP@ss12345!")
	_ = a.RevokeAllUserRefreshTokens(context.Background(), "secure@example.com")

	_, err := a.ValidateRefreshToken(context.Background(), rt1)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected rt1 revoked, got: %v", err)
	}
	_, err = a.ValidateRefreshToken(context.Background(), rt2)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected rt2 revoked, got: %v", err)
	}

	err = a.LoginUser(context.Background(), "secure@example.com", "NewP@ss12345!")
	if err != nil {
		t.Errorf("login with new password should succeed: %v", err)
	}

	rtNew, _ := a.GenerateRefreshToken(context.Background(), "secure@example.com")
	_, err = a.ValidateRefreshToken(context.Background(), rtNew)
	if err != nil {
		t.Errorf("new refresh token should be valid: %v", err)
	}
}

/* ======================== Combined: Rate Limiter + OTP ======================== */

/*
TestIntegrationRateLimitedOTPVerification tests rate limiting on OTP guessing.
*/
func TestIntegrationRateLimitedOTPVerification(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t)
	db := getTestDBPool(t, context.Background())

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	defer rl.Stop()

	expiry := time.Now().Add(5 * time.Minute)
	_, _ = db.Exec(context.Background(),
		"INSERT INTO otps (email, code, expires_at) VALUES ($1, $2, $3)",
		"otprl@example.com", computeTestOTPHash("999888"), expiry,
	)

	otpKey := "otp:otprl@example.com"

	for i := 0; i < 5; i++ {
		_ = rl.Allow(context.Background(), otpKey)
		_ = a.VerifyOTP(context.Background(), "otprl@example.com", "000000")
	}

	err := rl.Allow(context.Background(), otpKey)
	if !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Errorf("expected rate limit exceeded, got: %v", err)
	}
}

/* ======================== Full Auth Flow ======================== */

/*
TestIntegrationFullAuthFlow tests a realistic full application flow:
register -> RBAC setup -> rate-limited login -> JWT + refresh ->
check permissions -> rotate -> change password -> revoke all -> re-login.
*/
func TestIntegrationFullAuthFlow(t *testing.T) {
	skipIfShort(t)
	a := setupTestAuth(t, auth.WithJWT([]byte("full-flow-secret"), 24*time.Hour))

	rl, _ := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 10,
		Window:      time.Minute,
	})
	defer rl.Stop()

	_ = a.CreateSpace(context.Background(), "dashboard", 1)
	_ = a.CreateRole(context.Background(), "viewer")
	_ = a.CreateRole(context.Background(), "admin")

	err := a.RegisterUser(context.Background(), "fulltest@example.com", "MyS3cureP@ss")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_ = a.CreatePermissions(context.Background(), "fulltest@example.com", "dashboard", "viewer")

	_ = rl.Allow(context.Background(), "fulltest@example.com")
	err = a.LoginUser(context.Background(), "fulltest@example.com", "MyS3cureP@ss")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	jwt, _ := a.GenerateToken(context.Background(), "fulltest@example.com")
	rt, _ := a.GenerateRefreshToken(context.Background(), "fulltest@example.com")

	claims, _ := a.LoginJWT(context.Background(), jwt)

	err = a.CheckPermissions(context.Background(), claims.UserID, "dashboard", "viewer")
	if err != nil {
		t.Errorf("user should have viewer permission: %v", err)
	}

	err = a.CheckPermissions(context.Background(), claims.UserID, "dashboard", "admin")
	if err == nil {
		t.Error("user should NOT have admin permission")
	}

	newRT, userID, err := a.RotateRefreshToken(context.Background(), rt)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if userID != "fulltest@example.com" {
		t.Errorf("unexpected user: %s", userID)
	}

	_ = a.ChangePass(context.Background(), "fulltest@example.com", "NewP@ssw0rd!")
	_ = a.RevokeAllUserRefreshTokens(context.Background(), "fulltest@example.com")

	_, err = a.ValidateRefreshToken(context.Background(), newRT)
	if !errors.Is(err, auth.ErrRefreshTokenRevoked) {
		t.Errorf("expected revoked, got: %v", err)
	}

	err = a.LoginUser(context.Background(), "fulltest@example.com", "NewP@ssw0rd!")
	if err != nil {
		t.Fatalf("re-login failed: %v", err)
	}

	newJWT, _ := a.GenerateToken(context.Background(), "fulltest@example.com")
	finalClaims, err := a.ValidateToken(context.Background(), newJWT)
	if err != nil {
		t.Fatalf("failed to validate new JWT: %v", err)
	}
	if finalClaims.UserID != "fulltest@example.com" {
		t.Errorf("unexpected final UserID: %s", finalClaims.UserID)
	}

	newFinalRT, _ := a.GenerateRefreshToken(context.Background(), "fulltest@example.com")
	_, err = a.ValidateRefreshToken(context.Background(), newFinalRT)
	if err != nil {
		t.Errorf("final refresh token should be valid: %v", err)
	}
}
