package tests

import (
	"context"
	"testing"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/* ======================== Init / Close ======================== */

/*
TestInitEmptyInputs verifies that Auth Options reject empty required fields.
*/
func TestInitEmptyInputs(t *testing.T) {
	/* WithStorage is tested separately, but let's test WithSMTP directly or via New. */
	if err := auth.WithStorage(nil)(new(auth.Auth)); err == nil {
		t.Error("expected error for nil storage")
	}
}

/*
TestSMTPInitEmptyInputs verifies that WithSMTP rejects empty fields.
*/
func TestSMTPInitEmptyInputs(t *testing.T) {
	ctx := context.Background()

	if _, err := auth.New(ctx, auth.WithSMTP("", "pass", "host", "587")); err == nil {
		t.Error("expected error for empty email")
	}
	if _, err := auth.New(ctx, auth.WithSMTP("user@test.com", "", "host", "587")); err == nil {
		t.Error("expected error for empty password")
	}
	if _, err := auth.New(ctx, auth.WithSMTP("user@test.com", "pass", "", "587")); err == nil {
		t.Error("expected error for empty host")
	}
	if _, err := auth.New(ctx, auth.WithSMTP("user@test.com", "pass", "host", "")); err == nil {
		t.Error("expected error for empty port")
	}
}

/*
TestSMTPInitValid verifies that WithSMTP accepts valid input.
*/
func TestSMTPInitValid(t *testing.T) {
	ctx := context.Background()

	if _, err := auth.New(ctx, auth.WithSMTP("user@example.com", "password", "smtp.example.com", "587")); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

/*
TestCloseDoesNotPanic verifies that Close does not panic on a freshly init'd Auth.
*/
func TestCloseDoesNotPanic(t *testing.T) {
	a, _ := auth.New(context.Background())
	a.Close()
}

/* ======================== Refresh Token Config ======================== */

/*
TestRefreshTokenEmptyInputs verifies that empty inputs are rejected by Refresh Token methods.
*/
func TestRefreshTokenEmptyInputs(t *testing.T) {
	a, _ := auth.New(context.Background())

	if _, err := a.GenerateRefreshToken(context.Background(), ""); err == nil {
		t.Error("expected error for empty userID")
	}
	if _, err := a.ValidateRefreshToken(context.Background(), ""); err == nil {
		t.Error("expected error for empty token")
	}
	if err := a.RevokeRefreshToken(context.Background(), ""); err == nil {
		t.Error("expected error for empty token")
	}
	if err := a.RevokeAllUserRefreshTokens(context.Background(), ""); err == nil {
		t.Error("expected error for empty userID")
	}
}
