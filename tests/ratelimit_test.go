package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

/*
TestNewRateLimiter verifies that a rate limiter is created with valid config.
*/
func TestNewRateLimiter(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rl.Stop()

	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

/*
TestNewRateLimiterInvalidConfig checks that invalid configs are rejected.
*/
func TestNewRateLimiterInvalidConfig(t *testing.T) {
	_, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 0,
		Window:      time.Minute,
	})
	if err == nil {
		t.Error("expected error for MaxRequests=0")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: -1,
		Window:      time.Minute,
	})
	if err == nil {
		t.Error("expected error for negative MaxRequests")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      0,
	})
	if err == nil {
		t.Error("expected error for Window=0")
	}

	_, err = auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      -time.Second,
	})
	if err == nil {
		t.Error("expected error for negative Window")
	}
}

/*
TestRateLimiterAllow checks that requests within the limit are allowed.
*/
func TestRateLimiterAllow(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if err := rl.Allow(context.Background(), "user1"); err != nil {
			t.Errorf("request %d should be allowed, got: %v", i+1, err)
		}
	}
}

/*
TestRateLimiterExceeded checks that exceeding the limit returns an error.
*/
func TestRateLimiterExceeded(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		_ = rl.Allow(context.Background(), "user1")
	}

	err = rl.Allow(context.Background(), "user1")
	if err == nil {
		t.Error("expected rate limit exceeded error")
	}
}

/*
TestRateLimiterEmptyKey checks that empty keys are rejected.
*/
func TestRateLimiterEmptyKey(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	if err := rl.Allow(context.Background(), ""); err == nil {
		t.Error("expected error for empty key")
	}
}

/*
TestRateLimiterIsolation checks that different keys have independent limits.
*/
func TestRateLimiterIsolation(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user2"); err != nil {
		t.Errorf("user2 should not be rate limited, got: %v", err)
	}
}

/*
TestRateLimiterWindowExpiry verifies that old timestamps expire and free up capacity.
*/
func TestRateLimiterWindowExpiry(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err == nil {
		t.Error("expected rate limit exceeded")
	}

	time.Sleep(60 * time.Millisecond)

	if err := rl.Allow(context.Background(), "user1"); err != nil {
		t.Errorf("expected request to be allowed after window expiry, got: %v", err)
	}
}

/*
TestRateLimiterRemaining checks the remaining count logic.
*/
func TestRateLimiterRemaining(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	if r, _ := rl.Remaining(context.Background(), "user1"); r != 5 {
		t.Errorf("expected 5 remaining, got %d", r)
	}

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if r, _ := rl.Remaining(context.Background(), "user1"); r != 3 {
		t.Errorf("expected 3 remaining, got %d", r)
	}
}

/*
TestRateLimiterReset verifies that resetting a key clears its history.
*/
func TestRateLimiterReset(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err == nil {
		t.Error("expected rate limit exceeded before reset")
	}

	rl.Reset(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err != nil {
		t.Errorf("expected request to be allowed after reset, got: %v", err)
	}
}

/*
TestRateLimiterStop verifies that the stop function can be called multiple times safely.
*/
func TestRateLimiterStop(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	rl.Stop()
	rl.Stop()
}

/*
TestRateLimiterConcurrent tests that the rate limiter is safe
under concurrent access from multiple goroutines.
*/
func TestRateLimiterConcurrent(t *testing.T) {
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 100,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_ = rl.Allow(context.Background(), "concurrent-key")
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}

	remaining, _ := rl.Remaining(context.Background(), "concurrent-key")
	if remaining != 0 {
		t.Errorf("expected 0 remaining after 500 requests (limit 100), got %d", remaining)
	}
}

/* ======================== RedisRateLimiter Tests ======================== */

func TestRedisRateLimiterInitFailure(t *testing.T) {
	a, err := auth.New(context.Background())
	if err != nil {
		t.Fatalf("unexpected error creating Auth: %v", err)
	}

	_, err = a.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	if !errors.Is(err, auth.ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable, got: %v", err)
	}

	var nilAuth *auth.Auth
	if _, err := nilAuth.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	}); !errors.Is(err, auth.ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}
}

func TestRedisRateLimiterFallbackRemainingReset(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	client := redis.NewClient(&redis.Options{
		Addr:        server.Addr(),
		MaxRetries:  -1,
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := auth.New(context.Background(), auth.WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	const cooldown = 100 * time.Millisecond
	rl, err := a.NewRedisRateLimiterWithOptions(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	}, auth.WithRateLimitFallback(cooldown))
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	ctx := context.Background()
	if err := rl.Allow(ctx, "redis-before-outage"); err != nil {
		t.Fatal(err)
	}

	redisAddr := server.Addr()
	server.Close()

	if err := rl.Allow(ctx, "user1"); err != nil {
		t.Fatal(err)
	}
	if err := rl.Allow(ctx, "user1"); err != nil {
		t.Fatal(err)
	}
	if err := rl.Allow(ctx, "user1"); !errors.Is(err, auth.ErrRateLimitExceeded) {
		t.Fatalf("expected fallback limit to be enforced, got: %v", err)
	}

	if _, err := rl.Remaining(ctx, "user1"); !errors.Is(err, auth.ErrRateLimitBackendDown) {
		t.Fatalf("expected Remaining to report backend outage, got: %v", err)
	}
	if err := rl.Reset(ctx, "user1"); !errors.Is(err, auth.ErrRateLimitBackendDown) {
		t.Fatalf("expected Reset to report backend outage, got: %v", err)
	}

	time.Sleep(cooldown + 20*time.Millisecond)
	if err := server.StartAddr(redisAddr); err != nil {
		t.Fatalf("restart miniredis: %v", err)
	}

	if err := rl.Allow(ctx, "user1"); err != nil {
		t.Fatalf("expected Redis to be used after recovery, got: %v", err)
	}
	remaining, err := rl.Remaining(ctx, "user1")
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("expected Redis remaining count of 1 after recovery, got %d", remaining)
	}
}

func TestRedisRateLimiterAllow(t *testing.T) {
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}

	a := setupTestAuth(t, withRedisOption(t))

	rl, err := a.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 3,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rl.Stop()

	rl.Reset(context.Background(), "user1")

	for i := 0; i < 3; i++ {
		if err := rl.Allow(context.Background(), "user1"); err != nil {
			t.Errorf("request %d should be allowed, got: %v", i+1, err)
		}
	}

	if err := rl.Allow(context.Background(), "user1"); err == nil {
		t.Error("expected rate limit exceeded error")
	}
}

func TestRedisRateLimiterRemaining(t *testing.T) {
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}

	a := setupTestAuth(t, withRedisOption(t))

	rl, err := a.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 5,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	rl.Reset(context.Background(), "user1")

	if r, _ := rl.Remaining(context.Background(), "user1"); r != 5 {
		t.Errorf("expected 5 remaining, got %d", r)
	}

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if r, _ := rl.Remaining(context.Background(), "user1"); r != 3 {
		t.Errorf("expected 3 remaining, got %d", r)
	}
}

func TestRedisRateLimiterReset(t *testing.T) {
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}

	a := setupTestAuth(t, withRedisOption(t))

	rl, err := a.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	rl.Reset(context.Background(), "user1")

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err == nil {
		t.Error("expected rate limit exceeded before reset")
	}

	rl.Reset(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err != nil {
		t.Errorf("expected request to be allowed after reset, got: %v", err)
	}
}

func TestRedisRateLimiterExpiry(t *testing.T) {
	if !isRedisAvailable(t) {
		t.Skip("Redis is not available")
	}

	a := setupTestAuth(t, withRedisOption(t))

	rl, err := a.NewRedisRateLimiter(auth.RateLimiterConfig{
		MaxRequests: 2,
		Window:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	rl.Reset(context.Background(), "user1")

	_ = rl.Allow(context.Background(), "user1")
	_ = rl.Allow(context.Background(), "user1")

	if err := rl.Allow(context.Background(), "user1"); err == nil {
		t.Error("expected rate limit exceeded")
	}

	time.Sleep(100 * time.Millisecond)

	if err := rl.Allow(context.Background(), "user1"); err != nil {
		t.Errorf("expected request to be allowed after window expiry, got: %v", err)
	}
}
