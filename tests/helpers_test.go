package tests

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	authpg "github.com/GCET-Open-Source-Foundation/auth/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

/*
Test database connection constants.
These point to a local PostgreSQL instance used exclusively for testing.
*/
const (
	testDBPort    = 5432
	testDBUser    = "testuser"
	testDBPass    = "testpass"
	testDBName    = "testauth"
	testDBHost    = "127.0.0.1"
	testRedisHost = "127.0.0.1:6379"
	testRedisPass = ""
)

/*
setupTestAuth initialises a fully working Auth instance backed by a real
PostgreSQL database. Every call drops and recreates all library tables so
each test starts with a clean slate.

It registers a t.Cleanup callback that closes the Auth instance when the
test finishes.
*/
func setupTestAuth(t *testing.T, opts ...auth.Option) *auth.Auth {
	t.Helper()
	ctx := context.Background()

	/*
		Drop all tables before Init so we start clean every time.
		This works around a known Postgres case-sensitivity quirk: the
		library's CREATE TABLE uses camelCase column names (e.g. spaceName)
		but Postgres stores them lowercase. The schema checker then fails
		on subsequent Init() calls because it expects the camelCase variant.
	*/
	preCleanDB(t, ctx)

	storage, err := authpg.NewPostgresStorage(ctx, testDBPort, testDBUser, testDBPass, testDBName, testDBHost)
	if err != nil {
		t.Fatalf("failed to create PostgresStorage: %v", err)
	}

	defaultOpts := []auth.Option{
		auth.WithStorage(storage),
		auth.WithPepper([]byte("test_pepper")),
	}
	allOpts := append(defaultOpts, opts...)

	a, err := auth.New(ctx, allOpts...)
	if err != nil {
		t.Fatalf("failed to initialise Auth: %v", err)
	}

	t.Cleanup(func() {
		a.Close()
	})

	return a
}

/*
preCleanDB connects directly to the test database and drops every table
the library might have created, giving Init() a blank slate.
*/
func preCleanDB(t *testing.T, ctx context.Context) {
	t.Helper()

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		testDBUser, testDBPass, testDBHost, testDBPort, testDBName)
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("preCleanDB: failed to connect: %v", err)
	}
	defer pool.Close()

	pool.Exec(ctx, "DROP TABLE IF EXISTS permissions CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS refresh_tokens CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS otps CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS users CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS roles CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS spaces CASCADE")
}

/*
withRedisOption returns a WithRedis option for testing.
If Redis is not reachable, it should be handled in the test logic.
*/
func withRedisOption(t *testing.T) auth.Option {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:     testRedisHost,
		Password: testRedisPass,
		DB:       0,
	})
	return auth.WithRedis(rdb)
}

func isRedisAvailable(t *testing.T) bool {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:     testRedisHost,
		Password: testRedisPass,
		DB:       0,
	})
	defer rdb.Close()
	return rdb.Ping(context.Background()).Err() == nil
}

func withJWTOption(t *testing.T, secret string, expiry time.Duration) auth.Option {
	t.Helper()
	return auth.WithJWT([]byte(secret), expiry)
}

/*
computeTestOTPHash mirrors the library's HMAC-SHA256 keyed with the
test pepper so that tests inserting OTPs directly into the database
produce a hash that VerifyOTP can verify.
*/
func computeTestOTPHash(code string) string {
	mac := hmac.New(sha256.New, []byte("test_pepper"))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}
