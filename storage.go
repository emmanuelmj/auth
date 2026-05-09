package auth

import (
	"context"
	"time"
)

/* StorageEngine defines all database operations required by the Auth library. */
type StorageEngine interface {
	CheckTables(ctx context.Context) error

	// Users
	InsertUser(ctx context.Context, username, hash, salt string) error
	UpdateUserPassword(ctx context.Context, username, hash, salt string) (int64, error)
	DeleteUser(ctx context.Context, username string) error
	UserExists(ctx context.Context, username string) (bool, error)
	GetUserHashAndSalt(ctx context.Context, username string) (hash string, salt string, err error)
	ListUsers(ctx context.Context, limit, offset int) ([]User, error)
	UpsertOAuthUser(ctx context.Context, email string) error

	// Spaces
	InsertSpace(ctx context.Context, name string, authority int) error
	DeleteSpace(ctx context.Context, name string) error

	// Roles
	InsertRole(ctx context.Context, role string) error
	DeleteRole(ctx context.Context, role string) error

	// Permissions
	InsertPermission(ctx context.Context, username, spaceName, role string) error
	CheckPermissionExists(ctx context.Context, username, spaceName, role string) (bool, error)
	DeletePermission(ctx context.Context, username, spaceName, role string) error

	// OTP
	InsertOTP(ctx context.Context, email, code string, expiresAt time.Time) error
	GetOTP(ctx context.Context, email string) (code string, expiresAt time.Time, err error)
	DeleteOTP(ctx context.Context, email string) error
	ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error)
	CleanupExpiredOTPs(ctx context.Context) error

	// Refresh Tokens
	InsertRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, token string) (userID string, expiresAt time.Time, revoked bool, err error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) error
}
