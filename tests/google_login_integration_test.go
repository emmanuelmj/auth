package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

func loadIntegrationDBConfig(t *testing.T) (uint16, string, string, string, string) {
	t.Helper()

	host := os.Getenv("AUTH_TEST_DB_HOST")
	portStr := os.Getenv("AUTH_TEST_DB_PORT")
	user := os.Getenv("AUTH_TEST_DB_USER")
	pass := os.Getenv("AUTH_TEST_DB_PASS")
	name := os.Getenv("AUTH_TEST_DB_NAME")

	if host == "" || portStr == "" || user == "" || name == "" {
		t.Skipf("skipping integration test: set AUTH_TEST_DB_HOST, AUTH_TEST_DB_PORT, AUTH_TEST_DB_USER, AUTH_TEST_DB_PASS, AUTH_TEST_DB_NAME")
	}

	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("invalid AUTH_TEST_DB_PORT %q: %v", portStr, err)
	}

	return uint16(port64), user, pass, name, host
}

func newIntegrationAuth(t *testing.T) *auth.Auth {
	t.Helper()

	port, user, pass, dbName, host := loadIntegrationDBConfig(t)
	a, err := auth.Init(context.Background(), port, user, pass, dbName, host)
	if err != nil {
		t.Fatalf("failed to initialize auth: %v", err)
	}
	t.Cleanup(a.Close)

	if err := a.JWTInit("integration-jwt-secret"); err != nil {
		t.Fatalf("failed to initialize JWT secret: %v", err)
	}

	return a
}

func uniqueOAuthIdentity(prefix string) (email string, googleID string) {
	n := time.Now().UnixNano()
	return fmt.Sprintf("%s-%d@example.com", prefix, n), fmt.Sprintf("google-%s-%d", prefix, n)
}

func TestLoginWithGoogleCreatesUserAndIssuesJWT(t *testing.T) {
	a := newIntegrationAuth(t)
	ctx := context.Background()

	email, googleID := uniqueOAuthIdentity("oauth-create")
	t.Cleanup(func() {
		_, _ = a.Conn.Exec(ctx, "DELETE FROM users WHERE user_id = $1", email)
	})

	token, err := a.LoginWithGoogle(ctx, &auth.GoogleUser{
		ID:    googleID,
		Email: email,
		Name:  "OAuth Create",
	})
	if err != nil {
		t.Fatalf("LoginWithGoogle returned error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty JWT")
	}

	claims, err := a.LoginJWT(token)
	if err != nil {
		t.Fatalf("LoginJWT returned error: %v", err)
	}
	if claims.UserID != email {
		t.Fatalf("unexpected token user_id: got %q want %q", claims.UserID, email)
	}

	var authProvider, storedGoogleID, passwordHash, salt sql.NullString
	err = a.Conn.QueryRow(ctx, "SELECT auth_provider, google_id, password_hash, salt FROM users WHERE user_id = $1", email).
		Scan(&authProvider, &storedGoogleID, &passwordHash, &salt)
	if err != nil {
		t.Fatalf("failed to query inserted user: %v", err)
	}

	if !authProvider.Valid || authProvider.String != "google" {
		t.Fatalf("unexpected auth_provider: %#v", authProvider)
	}
	if !storedGoogleID.Valid || storedGoogleID.String != googleID {
		t.Fatalf("unexpected google_id: %#v", storedGoogleID)
	}
	if passwordHash.Valid || salt.Valid {
		t.Fatalf("expected oauth user password fields to be null, got password_hash=%#v salt=%#v", passwordHash, salt)
	}
}

func TestLoginWithGoogleLinksExistingLocalAccount(t *testing.T) {
	a := newIntegrationAuth(t)
	ctx := context.Background()

	email, googleID := uniqueOAuthIdentity("oauth-link")
	password := "StrongPass#123"

	if err := a.RegisterUser(email, password); err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = a.Conn.Exec(ctx, "DELETE FROM users WHERE user_id = $1", email)
	})

	token, err := a.LoginWithGoogle(ctx, &auth.GoogleUser{
		ID:    googleID,
		Email: email,
		Name:  "OAuth Link",
	})
	if err != nil {
		t.Fatalf("LoginWithGoogle returned error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty JWT")
	}

	if err := a.LoginUser(email, password); err != nil {
		t.Fatalf("password login should still work after linking, got: %v", err)
	}

	var authProvider, storedGoogleID, passwordHash, salt sql.NullString
	err = a.Conn.QueryRow(ctx, "SELECT auth_provider, google_id, password_hash, salt FROM users WHERE user_id = $1", email).
		Scan(&authProvider, &storedGoogleID, &passwordHash, &salt)
	if err != nil {
		t.Fatalf("failed to query linked user: %v", err)
	}

	if !authProvider.Valid || authProvider.String != "local" {
		t.Fatalf("expected local auth_provider to remain local, got %#v", authProvider)
	}
	if !storedGoogleID.Valid || storedGoogleID.String != googleID {
		t.Fatalf("unexpected google_id after linking: %#v", storedGoogleID)
	}
	if !passwordHash.Valid || !salt.Valid {
		t.Fatalf("expected local password fields to remain set, got password_hash=%#v salt=%#v", passwordHash, salt)
	}
}

func TestLoginWithGoogleRejectsGoogleIDMismatch(t *testing.T) {
	a := newIntegrationAuth(t)
	ctx := context.Background()

	email, firstGoogleID := uniqueOAuthIdentity("oauth-mismatch")
	secondGoogleID := firstGoogleID + "-other"

	t.Cleanup(func() {
		_, _ = a.Conn.Exec(ctx, "DELETE FROM users WHERE user_id = $1", email)
	})

	_, err := a.LoginWithGoogle(ctx, &auth.GoogleUser{
		ID:    firstGoogleID,
		Email: email,
		Name:  "OAuth First",
	})
	if err != nil {
		t.Fatalf("initial LoginWithGoogle failed: %v", err)
	}

	_, err = a.LoginWithGoogle(ctx, &auth.GoogleUser{
		ID:    secondGoogleID,
		Email: email,
		Name:  "OAuth Second",
	})
	if err == nil {
		t.Fatal("expected google_id mismatch to fail, got nil error")
	}
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}
