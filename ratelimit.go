package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

/*
RateLimiterConfig holds the configuration for the sliding-window rate limiter.
MaxRequests is the maximum number of requests allowed within the Window duration.
*/
type RateLimiterConfig struct {
	MaxRequests int
	Window      time.Duration
}

const rateLimitLuaScript = `
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local member = ARGV[4]
local clearBefore = now - window

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, clearBefore)
local count = redis.call('ZCARD', KEYS[1])

if count >= limit then
    return 0
end

redis.call('ZADD', KEYS[1], now, member)
redis.call('PEXPIRE', KEYS[1], window)
return 1
`

var rateLimitScript = redis.NewScript(rateLimitLuaScript)

/*
RateLimiter implements an in-memory, per-key sliding-window rate limiter.
It is safe for concurrent use. Keys are typically user IDs, IP addresses, or API keys.
*/
type RateLimiter struct {
	mu       sync.Mutex
	config   RateLimiterConfig
	buckets  map[string][]time.Time
	stopOnce sync.Once
	done     chan struct{}
}

/*
NewRateLimiter creates and returns a new RateLimiter with the given config.
It starts a background goroutine that periodically evicts stale entries
to prevent unbounded memory growth.
*/
func NewRateLimiter(cfg RateLimiterConfig) (*RateLimiter, error) {
	if cfg.MaxRequests <= 0 {
		return nil, ErrInvalidInput
	}
	if cfg.Window <= 0 {
		return nil, ErrInvalidInput
	}

	rl := &RateLimiter{
		config:  cfg,
		buckets: make(map[string][]time.Time),
		done:    make(chan struct{}),
	}

	go rl.cleanup()

	return rl, nil
}

/*
Allow checks whether a request identified by key should be allowed.
It records the current timestamp and returns nil if the request is within
the configured limit, or ErrRateLimitExceeded otherwise.
*/
func (rl *RateLimiter) Allow(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyInput
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.Window)

	/* Prune expired timestamps for this key */
	timestamps := rl.buckets[key]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= rl.config.MaxRequests {
		rl.buckets[key] = valid
		return ErrRateLimitExceeded
	}

	rl.buckets[key] = append(valid, now)
	return nil
}

/*
Remaining returns how many requests the Redis counter has left in the current
window. It never uses the in-memory fallback; Redis outages return
ErrRateLimitBackendDown because the local counter is not representative of
Redis state.
*/
func (rl *RateLimiter) Remaining(ctx context.Context, key string) (int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.Window)

	timestamps := rl.buckets[key]
	count := 0
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			count++
		}
	}

	remaining := rl.config.MaxRequests - count
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

/*
Reset clears the rate limit state for a specific key.
Useful when a user successfully authenticates and you want to clear failed-attempt counters.
It only resets Redis state and returns ErrRateLimitBackendDown rather than
reporting success if Redis cannot perform the reset.
*/
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
	return nil
}

/*
Stop shuts down the background cleanup goroutine.
Call this when the RateLimiter is no longer needed.
*/
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.done)
	})
}

/* cleanup periodically evicts expired timestamps to prevent memory leaks. */
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanPass()
		case <-rl.done:
			return
		}
	}
}

func (rl *RateLimiter) cleanPass() {
	rl.mu.Lock()
	keys := make([]string, 0, len(rl.buckets))
	for k := range rl.buckets {
		keys = append(keys, k)
	}
	rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.config.Window)
	for _, key := range keys {
		rl.mu.Lock()
		if timestamps, ok := rl.buckets[key]; ok {
			valid := timestamps[:0]
			for _, ts := range timestamps {
				if ts.After(cutoff) {
					valid = append(valid, ts)
				}
			}
			if len(valid) == 0 {
				delete(rl.buckets, key)
			} else {
				rl.buckets[key] = valid
			}
		}
		rl.mu.Unlock()
	}
}

/*
RedisRateLimiter implements a Redis-backed sliding-window rate limiter.
When explicitly enabled, its in-memory fallback is per limiter instance and
does not synchronize with Redis or other limiter instances. After Redis
recovers, local counters are not reconciled with Redis. An operation that
times out may have executed on Redis even though the client observed an error;
fallback therefore does not provide exactly-once behavior.
*/
type RedisRateLimiter struct {
	client           *redis.Client
	config           RateLimiterConfig
	fallbackEnabled  bool
	fallbackCooldown time.Duration
	onFallback       func(error)
	retryAt          atomic.Int64
	fallbackMu       sync.Mutex
	fallback         *RateLimiter
	stopped          bool
}

const redisRateLimitProbeInProgress int64 = -1
const redisRateLimitFallbackNotifying int64 = -2

type redisRateLimiterOptions struct {
	fallbackEnabled  bool
	fallbackCooldown time.Duration
	onFallback       func(error)
}

/*
RedisRateLimiterOption configures optional Redis rate limiter behavior.
*/
type RedisRateLimiterOption func(*redisRateLimiterOptions) error

/*
WithRateLimitFallbackCallback registers a callback for Redis failures that
activate an enabled in-memory fallback. It runs synchronously outside limiter
locks, before Allow uses the fallback, and at most once per outage activation.
The callback may call limiter methods without deadlocking; during the callback
those methods observe the active outage. It should return promptly and protect
any application state it captures.
*/
func WithRateLimitFallbackCallback(callback func(error)) RedisRateLimiterOption {
	return func(opts *redisRateLimiterOptions) error {
		if callback == nil {
			return ErrInvalidInput
		}
		opts.onFallback = callback
		return nil
	}
}

/*
WithRateLimitFallback enables a per-limiter in-memory fallback for Allow calls
when Redis is unavailable. The fallback is not distributed and does not
synchronize its counter with Redis; it weakens distributed rate-limit
guarantees and its counters are not reconciled when Redis recovers. A timed-out
Redis operation may have executed before the error was returned, so fallback
does not provide exactly-once behavior. While Redis is unavailable, Allow
returns the local limiter's result. Redis is retried after cooldown.
*/
func WithRateLimitFallback(cooldown time.Duration) RedisRateLimiterOption {
	return func(opts *redisRateLimiterOptions) error {
		if cooldown <= 0 {
			return ErrInvalidInput
		}
		opts.fallbackEnabled = true
		opts.fallbackCooldown = cooldown
		return nil
	}
}

/*
NewRedisRateLimiter creates and returns a new RedisRateLimiter.
It requires an initialized Auth instance with Redis configured. Redis failures
are fail-closed unless fallback is explicitly enabled with
NewRedisRateLimiterWithOptions.
*/
func (a *Auth) NewRedisRateLimiter(cfg RateLimiterConfig) (*RedisRateLimiter, error) {
	return a.NewRedisRateLimiterWithOptions(cfg)
}

/*
NewRedisRateLimiterWithOptions creates a RedisRateLimiter with optional
behavior such as an explicitly enabled in-memory fallback.
*/
func (a *Auth) NewRedisRateLimiterWithOptions(cfg RateLimiterConfig, options ...RedisRateLimiterOption) (*RedisRateLimiter, error) {
	if a == nil {
		return nil, ErrNotInitialized
	}
	if a.redisClient == nil {
		return nil, ErrRedisUnavailable
	}
	if cfg.MaxRequests <= 0 || cfg.Window <= 0 {
		return nil, ErrInvalidInput
	}

	opts := redisRateLimiterOptions{}
	for _, option := range options {
		if option == nil {
			return nil, ErrInvalidInput
		}
		if err := option(&opts); err != nil {
			return nil, err
		}
	}

	return &RedisRateLimiter{
		client:           a.redisClient,
		config:           cfg,
		fallbackEnabled:  opts.fallbackEnabled,
		fallbackCooldown: opts.fallbackCooldown,
		onFallback:       opts.onFallback,
	}, nil
}

func (rl *RedisRateLimiter) allowWithFallback(ctx context.Context, key string) error {
	if !rl.fallbackEnabled {
		return ErrRateLimitBackendDown
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	rl.fallbackMu.Lock()
	if rl.fallback == nil {
		fallback, err := NewRateLimiter(rl.config)
		if err != nil {
			rl.fallbackMu.Unlock()
			return err
		}
		rl.fallback = fallback
		if rl.stopped {
			fallback.Stop()
		}
	}
	fallback := rl.fallback
	rl.fallbackMu.Unlock()

	return fallback.Allow(ctx, key)
}

func (rl *RedisRateLimiter) recordRedisFailure(err error, recoveryAttempt bool) error {
	wrappedErr := fmt.Errorf("%w: %w", ErrRateLimitBackendDown, err)
	if !rl.fallbackEnabled {
		return wrappedErr
	}

	for {
		state := rl.retryAt.Load()
		if recoveryAttempt {
			if state != redisRateLimitProbeInProgress {
				return wrappedErr
			}
		} else if state != 0 {
			return wrappedErr
		}

		nextState := time.Now().Add(rl.fallbackCooldown).UnixNano()
		if rl.onFallback != nil {
			nextState = redisRateLimitFallbackNotifying
		}
		if !rl.retryAt.CompareAndSwap(state, nextState) {
			continue
		}
		break
	}

	if rl.onFallback != nil {
		defer func() {
			rl.retryAt.Store(time.Now().Add(rl.fallbackCooldown).UnixNano())
		}()
		rl.onFallback(wrappedErr)
	}
	return wrappedErr
}

func (rl *RedisRateLimiter) beginRedisAttempt() (useFallback, recoveryAttempt bool) {
	if !rl.fallbackEnabled {
		return false, false
	}

	for {
		retryAt := rl.retryAt.Load()
		switch {
		case retryAt == 0:
			return false, false
		case retryAt == redisRateLimitProbeInProgress || retryAt == redisRateLimitFallbackNotifying:
			return true, false
		case time.Now().UnixNano() < retryAt:
			return true, false
		case rl.retryAt.CompareAndSwap(retryAt, redisRateLimitProbeInProgress):
			return false, true
		}
	}
}

func (rl *RedisRateLimiter) recordRedisSuccess(recoveryAttempt bool) {
	if recoveryAttempt {
		rl.retryAt.CompareAndSwap(redisRateLimitProbeInProgress, 0)
	}
}

func (rl *RedisRateLimiter) cancelRecoveryAttempt(recoveryAttempt bool) {
	if recoveryAttempt {
		rl.retryAt.CompareAndSwap(redisRateLimitProbeInProgress, 0)
	}
}

func (rl *RedisRateLimiter) Allow(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyInput
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	useFallback, recoveryAttempt := rl.beginRedisAttempt()
	if useFallback {
		return rl.allowWithFallback(ctx, key)
	}

	now := time.Now()
	windowMs := rl.config.Window.Milliseconds()
	nowMs := now.UnixMilli()
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		rl.cancelRecoveryAttempt(recoveryAttempt)
		return fmt.Errorf("generate rate-limit request identifier: %w", err)
	}

	member := hex.EncodeToString(raw[:])

	res, err := rateLimitScript.Run(
		ctx,
		rl.client,
		[]string{"ratelimit:" + key},
		windowMs,
		rl.config.MaxRequests,
		nowMs,
		member,
	).Result()

	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			rl.cancelRecoveryAttempt(recoveryAttempt)
			return ctxErr
		}
		if rl.fallbackEnabled {
			rl.recordRedisFailure(err, recoveryAttempt)
			return rl.allowWithFallback(ctx, key)
		}
		return rl.recordRedisFailure(err, recoveryAttempt)
	}
	if allowed, ok := res.(int64); ok {
		switch allowed {
		case 1:
			rl.recordRedisSuccess(recoveryAttempt)
			return nil
		case 0:
			rl.recordRedisSuccess(recoveryAttempt)
			return ErrRateLimitExceeded
		}
	}
	err = fmt.Errorf("unexpected rate-limit script result %T(%v)", res, res)
	if rl.fallbackEnabled {
		rl.recordRedisFailure(err, recoveryAttempt)
		return rl.allowWithFallback(ctx, key)
	}
	return rl.recordRedisFailure(err, recoveryAttempt)
}

func (rl *RedisRateLimiter) Remaining(ctx context.Context, key string) (int, error) {
	if key == "" {
		return 0, ErrEmptyInput
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	useFallback, recoveryAttempt := rl.beginRedisAttempt()
	if useFallback {
		return 0, fmt.Errorf("%w: retrying Redis after fallback cooldown", ErrRateLimitBackendDown)
	}

	now := time.Now()
	cutoffMs := now.UnixMilli() - rl.config.Window.Milliseconds()

	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, "ratelimit:"+key, "0", fmt.Sprintf("%d", cutoffMs))
	countCmd := pipe.ZCard(ctx, "ratelimit:"+key)
	_, err := pipe.Exec(ctx)

	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			rl.cancelRecoveryAttempt(recoveryAttempt)
			return 0, ctxErr
		}
		return 0, rl.recordRedisFailure(err, recoveryAttempt)
	}
	if err := countCmd.Err(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			rl.cancelRecoveryAttempt(recoveryAttempt)
			return 0, ctxErr
		}
		return 0, rl.recordRedisFailure(err, recoveryAttempt)
	}

	rl.recordRedisSuccess(recoveryAttempt)
	count := countCmd.Val()
	remaining := rl.config.MaxRequests - int(count)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}

func (rl *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return ErrEmptyInput
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	useFallback, recoveryAttempt := rl.beginRedisAttempt()
	if useFallback {
		return fmt.Errorf("%w: retrying Redis after fallback cooldown", ErrRateLimitBackendDown)
	}

	err := rl.client.Del(ctx, "ratelimit:"+key).Err()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			rl.cancelRecoveryAttempt(recoveryAttempt)
			return ctxErr
		}
		return rl.recordRedisFailure(err, recoveryAttempt)
	}

	rl.recordRedisSuccess(recoveryAttempt)
	return nil
}

/*
Stop shuts down the in-memory fallback cleanup goroutine if it was created.
Call this when the RedisRateLimiter is no longer needed.
*/
func (rl *RedisRateLimiter) Stop() {
	if rl == nil {
		return
	}

	rl.fallbackMu.Lock()
	rl.stopped = true
	fallback := rl.fallback
	rl.fallbackMu.Unlock()

	if fallback != nil {
		fallback.Stop()
	}
}
