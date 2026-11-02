package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisRateLimiterDoesNotCreateFallbackByDefault(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	client := redis.NewClient(&redis.Options{
		Addr:       server.Addr(),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	rl, err := a.NewRedisRateLimiter(RateLimiterConfig{
		MaxRequests: 1,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rl.Allow(cancelledCtx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Allow to preserve context cancellation, got: %v", err)
	}
	if _, err := rl.Remaining(cancelledCtx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Remaining to preserve context cancellation, got: %v", err)
	}
	if err := rl.Reset(cancelledCtx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Reset to preserve context cancellation, got: %v", err)
	}

	if rl.fallback != nil {
		t.Fatal("fallback limiter should not be allocated before a Redis outage")
	}

	server.Close()
	if err := rl.Allow(context.Background(), "key"); !errors.Is(err, ErrRateLimitBackendDown) {
		t.Fatalf("expected backend-down error, got: %v", err)
	}
	if _, err := rl.Remaining(context.Background(), "key"); !errors.Is(err, ErrRateLimitBackendDown) {
		t.Fatalf("expected Remaining to report backend outage, got: %v", err)
	}
	if err := rl.Reset(context.Background(), "key"); !errors.Is(err, ErrRateLimitBackendDown) {
		t.Fatalf("expected Reset to report DEL failure, got: %v", err)
	}
	if rl.fallback != nil {
		t.Fatal("fallback limiter was created while fallback was disabled")
	}
}

func TestWithRedisDefersRedisErrorsUntilOperation(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:       "127.0.0.1:0",
		MaxRetries: -1,
	})
	defer func() { _ = client.Close() }()

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatalf("Auth initialization should not connect to Redis: %v", err)
	}
	defer a.Close()

	rl, err := a.NewRedisRateLimiter(RateLimiterConfig{
		MaxRequests: 1,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	if err := rl.Allow(context.Background(), "key"); !errors.Is(err, ErrRateLimitBackendDown) {
		t.Fatalf("expected operation to report Redis failure, got: %v", err)
	}
}

func TestRedisRateLimiterReloadsFlushedScript(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	client := redis.NewClient(&redis.Options{
		Addr:       server.Addr(),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	rl, err := a.NewRedisRateLimiter(RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	ctx := context.Background()
	if err := rl.Allow(ctx, "script-key"); err != nil {
		t.Fatal(err)
	}
	if err := client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("flush Redis scripts: %v", err)
	}
	if err := rl.Allow(ctx, "script-key"); err != nil {
		t.Fatalf("expected Script.Run to recover from NOSCRIPT, got: %v", err)
	}
	remaining, err := rl.Remaining(ctx, "script-key")
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expected two requests recorded after script reload, got %d remaining", remaining)
	}
}

func TestRedisRateLimiterConcurrentFailuresPreserveRecoveryProbe(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	client := redis.NewClient(&redis.Options{
		Addr:       server.Addr(),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	rl, err := a.NewRedisRateLimiterWithOptions(RateLimiterConfig{
		MaxRequests: 64,
		Window:      time.Minute,
	}, WithRateLimitFallback(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	rl.retryAt.Store(time.Now().Add(-time.Millisecond).UnixNano())
	useFallback, recoveryAttempt := rl.beginRedisAttempt()
	if useFallback || !recoveryAttempt {
		t.Fatal("expected to claim an expired cooldown for recovery")
	}

	const failures = 32
	var wg sync.WaitGroup
	for i := 0; i < failures; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.recordRedisFailure(errors.New("concurrent Redis failure"), false)
		}()
	}
	wg.Wait()

	if state := rl.retryAt.Load(); state != redisRateLimitProbeInProgress {
		t.Fatalf("concurrent failure overwrote recovery probe state: %d", state)
	}

	rl.recordRedisSuccess(recoveryAttempt)
	if state := rl.retryAt.Load(); state != 0 {
		t.Fatalf("successful recovery probe did not clear outage state: %d", state)
	}
}

func TestRedisRateLimiterFallbackCallbackCanReenter(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:       "127.0.0.1:0",
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	var rl *RedisRateLimiter
	callbackCalled := make(chan error, 1)
	rl, err = a.NewRedisRateLimiterWithOptions(RateLimiterConfig{
		MaxRequests: 2,
		Window:      time.Minute,
	}, WithRateLimitFallback(time.Second), WithRateLimitFallbackCallback(func(err error) {
		callbackCalled <- err
		if nestedErr := rl.Allow(context.Background(), "callback-key"); nestedErr != nil {
			callbackCalled <- nestedErr
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	if err := rl.Allow(context.Background(), "key"); err != nil {
		t.Fatalf("expected fallback Allow to preserve its decision semantics, got: %v", err)
	}
	select {
	case err := <-callbackCalled:
		if !errors.Is(err, ErrRateLimitBackendDown) {
			t.Fatalf("callback should receive backend error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback callback was not invoked")
	}
}

func TestRedisRateLimiterConcurrentFallbackInitialization(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	client := redis.NewClient(&redis.Options{
		Addr:       server.Addr(),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	a, err := New(context.Background(), WithRedis(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	rl, err := a.NewRedisRateLimiterWithOptions(RateLimiterConfig{
		MaxRequests: 64,
		Window:      time.Minute,
	}, WithRateLimitFallback(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Stop()

	if rl.fallback != nil {
		t.Fatal("fallback limiter should not be allocated before a Redis outage")
	}

	server.Close()

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- rl.Allow(context.Background(), "key")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("fallback Allow failed: %v", err)
		}
	}

	if rl.fallback == nil {
		t.Fatal("expected concurrent outage to initialize the fallback")
	}
}
