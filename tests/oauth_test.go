package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"golang.org/x/oauth2"
)

type googleOAuthTestTransport struct {
	email         string
	verifiedEmail bool
}

func (rt googleOAuthTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string
	switch req.URL.Host {
	case "oauth2.googleapis.com":
		body = `{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`
	case "www.googleapis.com":
		profile, err := json.Marshal(map[string]any{
			"id":             "google-test-id",
			"email":          rt.email,
			"verified_email": rt.verifiedEmail,
		})
		if err != nil {
			return nil, err
		}
		body = string(profile)
	default:
		return nil, fmt.Errorf("unexpected OAuth test request host %q", req.URL.Host)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func newGoogleCallbackContext(email string, verified bool) context.Context {
	client := &http.Client{Transport: googleOAuthTestTransport{email: email, verifiedEmail: verified}}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

func setupGoogleOAuthTest(t *testing.T) *auth.Auth {
	t.Helper()
	return setupTestAuth(t,
		auth.WithOAuth("test-client-id", "test-client-secret", "http://localhost/callback"),
		auth.WithJWT([]byte("oauth-test-signing-secret"), time.Hour),
	)
}

func TestIntegrationGoogleOAuthRejectsUnverifiedProviderEmail(t *testing.T) {
	skipIfShort(t)
	const email = "google-unverified-claim@example.com"
	a := setupGoogleOAuthTest(t)

	jwt, err := a.HandleGoogleCallback(newGoogleCallbackContext(email, false), "test-code")
	if err == nil || jwt != "" {
		t.Fatalf("expected unverified Google identity to fail without a JWT, jwt=%q err=%v", jwt, err)
	}
	var exists bool
	if err := getTestDBPool(t, context.Background()).QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)", email).Scan(&exists); err != nil {
		t.Fatalf("failed to check Google account: %v", err)
	}
	if exists {
		t.Fatal("unverified Google identity created an account")
	}
}

func TestIntegrationGoogleOAuthRejectsUnverifiedClaimForExistingLocalAccount(t *testing.T) {
	skipIfShort(t)
	const email = "google-unverified-existing-local@example.com"
	a := setupGoogleOAuthTest(t)
	db := getTestDBPool(t, context.Background())
	const hash = "existing-local-hash"
	const salt = "existing-local-salt"
	if _, err := db.Exec(context.Background(), "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", email, hash, salt); err != nil {
		t.Fatalf("failed to create local account: %v", err)
	}

	jwt, err := a.HandleGoogleCallback(newGoogleCallbackContext(email, false), "test-code")
	if err == nil || jwt != "" {
		t.Fatalf("expected unverified provider claim to fail without JWT, jwt=%q err=%v", jwt, err)
	}
	var storedHash, storedSalt string
	var verified bool
	if err := db.QueryRow(context.Background(), "SELECT password_hash, salt, email_verified FROM users WHERE user_id = $1", email).Scan(&storedHash, &storedSalt, &verified); err != nil {
		t.Fatalf("failed to read local account: %v", err)
	}
	if storedHash != hash || storedSalt != salt || verified {
		t.Fatal("unverified Google identity changed the existing local account")
	}
}

func TestIntegrationGoogleOAuthCreatesVerifiedNewAccount(t *testing.T) {
	skipIfShort(t)
	const email = "google-new@example.com"
	a := setupGoogleOAuthTest(t)
	ctx := newGoogleCallbackContext(email, true)

	jwt, err := a.HandleGoogleCallback(ctx, "test-code")
	if err != nil || jwt == "" {
		t.Fatalf("expected verified Google identity to sign in, jwt=%q err=%v", jwt, err)
	}
	var verified bool
	if err := getTestDBPool(t, context.Background()).QueryRow(context.Background(), "SELECT email_verified FROM users WHERE user_id = $1", email).Scan(&verified); err != nil {
		t.Fatalf("failed to read new Google user's verification state: %v", err)
	}
	if !verified {
		t.Fatal("new Google account was not marked verified")
	}
}

func TestIntegrationGoogleOAuthPreservesVerifiedLocalAccount(t *testing.T) {
	skipIfShort(t)
	const email = "google-existing-verified@example.com"
	a := setupGoogleOAuthTest(t)
	db := getTestDBPool(t, context.Background())
	const hash = "local-password-hash"
	const salt = "local-password-salt"
	if _, err := db.Exec(context.Background(), "INSERT INTO users (user_id, password_hash, salt, email_verified) VALUES ($1, $2, $3, true)", email, hash, salt); err != nil {
		t.Fatalf("failed to create verified local account: %v", err)
	}

	jwt, err := a.HandleGoogleCallback(newGoogleCallbackContext(email, true), "test-code")
	if err != nil || jwt == "" {
		t.Fatalf("expected verified local account to sign in, jwt=%q err=%v", jwt, err)
	}
	var storedHash, storedSalt string
	if err := db.QueryRow(context.Background(), "SELECT password_hash, salt FROM users WHERE user_id = $1", email).Scan(&storedHash, &storedSalt); err != nil {
		t.Fatalf("failed to read linked local account: %v", err)
	}
	if storedHash != hash || storedSalt != salt {
		t.Fatal("Google sign-in overwrote the local password hash or salt")
	}
}

func TestIntegrationGoogleOAuthRejectsUnverifiedLocalAccount(t *testing.T) {
	skipIfShort(t)
	const email = "google-existing-unverified@example.com"
	a := setupGoogleOAuthTest(t)
	db := getTestDBPool(t, context.Background())
	const hash = "legacy-local-hash"
	const salt = "legacy-local-salt"
	if _, err := db.Exec(context.Background(), "INSERT INTO users (user_id, password_hash, salt) VALUES ($1, $2, $3)", email, hash, salt); err != nil {
		t.Fatalf("failed to create unverified local account: %v", err)
	}

	jwt, err := a.HandleGoogleCallback(newGoogleCallbackContext(email, true), "test-code")
	if !errors.Is(err, auth.ErrEmailNotVerified) || jwt != "" {
		t.Fatalf("expected unverified local account to be rejected without JWT, jwt=%q err=%v", jwt, err)
	}
	var storedHash, storedSalt string
	var verified bool
	if err := db.QueryRow(context.Background(), "SELECT password_hash, salt, email_verified FROM users WHERE user_id = $1", email).Scan(&storedHash, &storedSalt, &verified); err != nil {
		t.Fatalf("failed to read rejected local account: %v", err)
	}
	if storedHash != hash || storedSalt != salt || verified {
		t.Fatal("rejected Google sign-in changed the existing unverified local account")
	}
}

func TestIntegrationConcurrentGoogleOAuthCreation(t *testing.T) {
	skipIfShort(t)
	const email = "google-concurrent@example.com"
	a := setupGoogleOAuthTest(t)
	ctx := newGoogleCallbackContext(email, true)
	start := make(chan struct{})
	type result struct {
		jwt string
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			jwt, err := a.HandleGoogleCallback(ctx, "test-code")
			results <- result{jwt: jwt, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for got := range results {
		if got.err != nil || got.jwt == "" {
			t.Fatalf("concurrent verified OAuth sign-in failed: jwt=%q err=%v", got.jwt, got.err)
		}
	}
	var count int
	if err := getTestDBPool(t, context.Background()).QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE user_id = $1 AND email_verified = true", email).Scan(&count); err != nil {
		t.Fatalf("failed to check concurrently created account: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one verified account after concurrent OAuth creation, got %d", count)
	}
}
