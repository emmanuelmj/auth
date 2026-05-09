package tests

import (
	"context"
	"testing"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

/*
TestHashPasswordDeterministic checks that hashing the same password with
the same salt produces a consistent output.
*/
func TestHashPasswordDeterministic(t *testing.T) {
	a, _ := auth.New(context.Background())

	hash1, err := a.HashPassword("mypassword", "somesalt1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := a.HashPassword("mypassword", "somesalt1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("same password and salt should produce the same hash, got %s and %s", hash1, hash2)
	}
}

/*
TestHashPasswordDifferentSalt verifies that different salts produce different hashes.
*/
func TestHashPasswordDifferentSalt(t *testing.T) {
	a, _ := auth.New(context.Background())

	hash1, err := a.HashPassword("mypassword", "salt_one_1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := a.HashPassword("mypassword", "salt_two_1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("different salts should produce different hashes")
	}
}

/*
TestHashPasswordDifferentPasswords verifies that different passwords produce different hashes.
*/
func TestHashPasswordDifferentPasswords(t *testing.T) {
	a, _ := auth.New(context.Background())

	hash1, err := a.HashPassword("password1", "same_salt_1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := a.HashPassword("password2", "same_salt_1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("different passwords should produce different hashes")
	}
}

/*
TestHashPasswordWithPepper verifies that adding a pepper changes the hash output.
*/
func TestHashPasswordWithPepper(t *testing.T) {
	a, _ := auth.New(context.Background())

	hashWithout, err := a.HashPassword("mypassword", "somesalt1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, _ := auth.New(context.Background(), auth.WithPepper([]byte("my-secret-pepper")))
	hashWith, err := b.HashPassword("mypassword", "somesalt1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hashWithout == hashWith {
		t.Error("pepper should change the hash output")
	}
}

/*
TestDefaultSaltParameters validates the parameter boundary checking.
*/
func TestDefaultSaltParameters(t *testing.T) {
	a, _ := auth.New(context.Background())

	if err := a.DefaultSaltParameters(0, 64*1024, 4, 32); err == nil {
		t.Error("expected error for time=0")
	}
	/* Memory floor is now 32MB; 16MB (16*1024 KB) should trigger the guard. */
	if err := a.DefaultSaltParameters(3, 16*1024, 4, 32); err == nil {
		t.Error("expected error for memory below 32MB")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 0, 32); err == nil {
		t.Error("expected error for threads=0")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 4, 8); err == nil {
		t.Error("expected error for keyLen < 16")
	}
	if err := a.DefaultSaltParameters(3, 64*1024, 4, 32); err != nil {
		t.Errorf("expected no error for valid params, got: %v", err)
	}
}
