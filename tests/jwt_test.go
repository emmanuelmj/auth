package tests

import (
	"context"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestJWTInit verifies that the JWT secret and expiry are set correctly.
*/
func TestJWTInit(t *testing.T) {
	a, _ := auth.New(context.Background())

	/* Empty secret should fail */
	if err := a.JWTInit(context.Background(), ""); err == nil {
		t.Error("expected error for empty JWT secret")
	}

	/* Valid secret should succeed */
	if err := a.JWTInit(context.Background(), "my-secret-key"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

/*
TestJWTInitCustomExpiry verifies that a custom expiry is applied.
*/
func TestJWTInitCustomExpiry(t *testing.T) {
	a, _ := auth.New(context.Background())

	if err := a.JWTInit(context.Background(), "secret", 2*time.Hour); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	/* Generate and validate — if it works the expiry was accepted */
	token, err := a.GenerateToken(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	claims, err := a.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected 'testuser', got '%s'", claims.UserID)
	}
}

/*
TestJWTInitIdempotent verifies that JWTInit only sets the secret once.
*/
func TestJWTInitIdempotent(t *testing.T) {
	a, _ := auth.New(context.Background())

	_ = a.JWTInit(context.Background(), "first-secret")
	_ = a.JWTInit(context.Background(), "second-secret")

	/* Token generated should only work with the first secret */
	token, _ := a.GenerateToken(context.Background(), "testuser")

	b, _ := auth.New(context.Background())
	_ = b.JWTInit(context.Background(), "first-secret")

	_, err := b.ValidateToken(context.Background(), token)
	if err != nil {
		t.Error("token should validate with first secret (sync.Once should ignore second)")
	}
}

/*
TestGenerateToken verifies that a valid JWT is generated for a given user.
*/
func TestGenerateToken(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	token, err := a.GenerateToken(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Error("expected a non-empty token")
	}
}

/*
TestGenerateTokenEmpty checks that empty username is rejected.
*/
func TestGenerateTokenEmpty(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	_, err := a.GenerateToken(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty username")
	}
}

/*
TestGenerateTokenNotInitialized checks that token generation fails without JWTInit.
*/
func TestGenerateTokenNotInitialized(t *testing.T) {
	a, _ := auth.New(context.Background())

	_, err := a.GenerateToken(context.Background(), "testuser")
	if err == nil {
		t.Error("expected error when JWT is not initialized")
	}
}

/*
TestValidateToken verifies the full generate-then-validate round trip.
*/
func TestValidateToken(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	token, err := a.GenerateToken(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	claims, err := a.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error validating token: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected UserID 'testuser', got '%s'", claims.UserID)
	}
}

/*
TestValidateTokenExpired checks that an expired token is correctly rejected.
*/
func TestValidateTokenExpired(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	token, err := a.GenerateToken(context.Background(), "testuser", -1*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = a.ValidateToken(context.Background(), token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

/*
TestValidateTokenInvalidString checks that garbage input is rejected.
*/
func TestValidateTokenInvalidString(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	_, err := a.ValidateToken(context.Background(), "this.is.not.a.valid.jwt")
	if err == nil {
		t.Error("expected error for invalid token string")
	}
}

/*
TestValidateTokenWrongSecret checks that a token signed with a different secret fails.
*/
func TestValidateTokenWrongSecret(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "secret-one")

	token, err := a.GenerateToken(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, _ := auth.New(context.Background())
	_ = b.JWTInit(context.Background(), "secret-two")

	_, err = b.ValidateToken(context.Background(), token)
	if err == nil {
		t.Error("expected error when validating with wrong secret")
	}
}

/*
TestLoginJWT verifies that LoginJWT works as a pass-through to ValidateToken.
*/
func TestLoginJWT(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	token, err := a.GenerateToken(context.Background(), "jwtuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := a.LoginJWT(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error from LoginJWT: %v", err)
	}
	if claims.UserID != "jwtuser" {
		t.Errorf("expected UserID 'jwtuser', got '%s'", claims.UserID)
	}
}

/*
TestGenerateTokenCustomExpiry verifies that a custom expiry produces a valid token.
*/
func TestGenerateTokenCustomExpiry(t *testing.T) {
	a, _ := auth.New(context.Background())
	_ = a.JWTInit(context.Background(), "test-secret")

	token, err := a.GenerateToken(context.Background(), "testuser", 1*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := a.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "testuser" {
		t.Errorf("expected UserID 'testuser', got '%s'", claims.UserID)
	}
}

/*
FuzzValidateToken tests the JWT validation logic against arbitrary token strings.
It ensures that the token parser does not panic on malformed or malicious inputs.
*/
func FuzzValidateToken(f *testing.F) {
	// Provide a few seed inputs
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature")
	f.Add("invalid.token.format")
	f.Add("not.even.base64!!!")
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		// Use functional options for init as required by the new design
		a, err := auth.New(context.Background(), auth.WithJWT([]byte("fuzz-secret"), time.Hour))
		if err != nil {
			t.Fatalf("failed to init auth: %v", err)
		}

		// ValidateToken should not panic, it should cleanly return an error for invalid input
		_, _ = a.ValidateToken(context.Background(), token)
	})
}
