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

	hash1 := a.HashPassword("mypassword", "somesalt1234567890")
	hash2 := a.HashPassword("mypassword", "somesalt1234567890")

	if hash1 != hash2 {
		t.Errorf("same password and salt should produce the same hash, got %s and %s", hash1, hash2)
	}
}

/*
TestHashPasswordDifferentSalt verifies that different salts produce different hashes.
*/
func TestHashPasswordDifferentSalt(t *testing.T) {
	a, _ := auth.New(context.Background())

	hash1 := a.HashPassword("mypassword", "salt_one_1234567890")
	hash2 := a.HashPassword("mypassword", "salt_two_1234567890")

	if hash1 == hash2 {
		t.Error("different salts should produce different hashes")
	}
}

/*
TestHashPasswordDifferentPasswords verifies that different passwords produce different hashes.
*/
func TestHashPasswordDifferentPasswords(t *testing.T) {
	a, _ := auth.New(context.Background())

	hash1 := a.HashPassword("password1", "same_salt_1234567890")
	hash2 := a.HashPassword("password2", "same_salt_1234567890")

	if hash1 == hash2 {
		t.Error("different passwords should produce different hashes")
	}
}

/*
TestHashPasswordWithPepper verifies that adding a pepper changes the hash output.
*/
func TestHashPasswordWithPepper(t *testing.T) {
	a, _ := auth.New(context.Background())

	hashWithout := a.HashPassword("mypassword", "somesalt1234567890")

	b, _ := auth.New(context.Background(), auth.WithPepper([]byte("my-secret-pepper")))
	hashWith := b.HashPassword("mypassword", "somesalt1234567890")

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
	if err := a.DefaultSaltParameters(3, 1024, 4, 32); err == nil {
		t.Error("expected error for memory below 8MB")
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
