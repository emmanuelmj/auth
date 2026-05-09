package tests

import (
	"context"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestRefreshTokenGenerateAndValidateWithRedis verifies that a refresh token
generated while Redis is active is cached and can be validated via the cache path.
*/
func TestRefreshTokenGenerateAndValidateWithRedis(t *testing.T) {
	skipIfShort(t)
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}
	a := setupTestAuth(t, withRedisOption(t), auth.WithRefreshToken(1*time.Hour, 32))

	userID := "redis-user-1@example.com"
	if err := a.RegisterUser(context.Background(), userID, "TestP@ssword1!"); err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	token, err := a.GenerateRefreshToken(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	if len(token) == 0 {
		t.Fatal("expected non-empty token")
	}

	validUserID, err := a.ValidateRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	}

	if validUserID != userID {
		t.Errorf("expected user ID %q, got %q", userID, validUserID)
	}
}

/*
TestRefreshTokenRevokeWithRedis verifies that revoking a token
removes it from both the database and the Redis cache.
*/
func TestRefreshTokenRevokeWithRedis(t *testing.T) {
	skipIfShort(t)
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}
	a := setupTestAuth(t, withRedisOption(t), auth.WithRefreshToken(1*time.Hour, 32))

	userID := "redis-user-2@example.com"
	if err := a.RegisterUser(context.Background(), userID, "TestP@ssword2!"); err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	token, err := a.GenerateRefreshToken(context.Background(), userID)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	err = a.RevokeRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error revoking token: %v", err)
	}

	_, err = a.ValidateRefreshToken(context.Background(), token)
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

/*
TestRevokeAllUserRefreshTokensWithRedis verifies that mass revocation
invalidates every token for the target user while leaving
other users' tokens intact.
*/
func TestRevokeAllUserRefreshTokensWithRedis(t *testing.T) {
	skipIfShort(t)
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}
	a := setupTestAuth(t, withRedisOption(t), auth.WithRefreshToken(1*time.Hour, 32))

	userID := "redis-user-3@example.com"
	if err := a.RegisterUser(context.Background(), userID, "TestP@ssword3!"); err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	token1, _ := a.GenerateRefreshToken(context.Background(), userID)
	token2, _ := a.GenerateRefreshToken(context.Background(), userID)

	if err := a.RegisterUser(context.Background(), "redis-other@example.com", "TestP@ssword4!"); err != nil {
		t.Fatalf("failed to register other user: %v", err)
	}
	otherToken, _ := a.GenerateRefreshToken(context.Background(), "redis-other@example.com")

	err := a.RevokeAllUserRefreshTokens(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := a.ValidateRefreshToken(context.Background(), token1); err == nil {
		t.Error("expected token1 to be invalid after mass revocation")
	}
	if _, err := a.ValidateRefreshToken(context.Background(), token2); err == nil {
		t.Error("expected token2 to be invalid after mass revocation")
	}

	if uid, err := a.ValidateRefreshToken(context.Background(), otherToken); err != nil || uid != "redis-other@example.com" {
		t.Errorf("expected other user's token to remain valid, got err: %v", err)
	}
}
