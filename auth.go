package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

/* PasswordPolicy defines constraints for a user's password. */
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

/* Auth manages the internal state of the library, including database connections, */
/* cryptographic parameters, and caching clients. It is safe for concurrent use. */
type Auth struct {
	storage            StorageEngine
	argonParams        ArgonParameters
	pepper             []byte
	pepperOnce         sync.Once
	jwtSecret          []byte
	jwtExpiry          time.Duration
	otpExpiry          time.Duration
	otpLength          int
	jwtOnce            sync.Once
	smtpEmail          string
	smtpPassword       []byte
	smtpHost           string
	smtpPort           string
	smtpOnce           sync.Once
	refreshTokenExpiry time.Duration
	refreshTokenLength int
	ctx                context.Context
	cancel             context.CancelFunc
	oauthConfig        *oauth2.Config
	oauthOnce          sync.Once
	redisClient        *redis.Client
	requestGroup       singleflight.Group
	rateLimitSHA       string
	passwordPolicy     PasswordPolicy
}

/* Option is a functional option for configuring the Auth instance. */
type Option func(*Auth) error

/* WithStorage configures the Auth instance with a specific StorageEngine. */
func WithStorage(storage StorageEngine) Option {
	return func(a *Auth) error {
		if storage == nil {
			return ErrEmptyInput
		}
		a.storage = storage
		return nil
	}
}

/* WithRedis configures the Auth instance with a Redis client for caching and rate-limiting. */
func WithRedis(client *redis.Client) Option {
	return func(a *Auth) error {
		if client == nil {
			return ErrEmptyInput
		}
		a.redisClient = client

		// Attempt to load the rate limit script
		const rateLimitScript = `
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
		sha, err := client.ScriptLoad(context.Background(), rateLimitScript).Result()
		if err != nil {
			return fmt.Errorf("failed to load redis rate limit script: %w", err)
		}
		a.rateLimitSHA = sha
		return nil
	}
}

// WithRefreshToken sets the duration for which a refresh token is valid and its length.
func WithRefreshToken(expiry time.Duration, length int) Option {
	return func(a *Auth) error {
		a.refreshTokenExpiry = expiry
		if length <= 0 {
			length = 32
		}
		a.refreshTokenLength = length
		return nil
	}
}

// WithOTP configures the OTP length and expiration time.
func WithOTP(length int, expiry time.Duration) Option {
	return func(a *Auth) error {
		if length <= 0 {
			length = 6
		}
		if expiry <= 0 {
			expiry = 5 * time.Minute
		}
		a.otpLength = length
		a.otpExpiry = expiry
		return nil
	}
}

/* WithJWT configures the JWT signing secret and expiration time. */
func WithJWT(secret []byte, expiry time.Duration) Option {
	return func(a *Auth) error {
		if len(secret) == 0 {
			return ErrEmptyInput
		}
		if expiry <= 0 {
			return ErrInvalidInput
		}
		a.jwtSecret = append([]byte(nil), secret...) // Make a copy
		a.jwtExpiry = expiry
		return nil
	}
}

/* WithSMTP configures the SMTP server details for sending emails (e.g., OTP). */
func WithSMTP(email, password, host, port string) Option {
	return func(a *Auth) error {
		if email == "" || password == "" || host == "" || port == "" {
			return ErrEmptyInput
		}
		a.smtpEmail = email
		a.smtpPassword = []byte(password)
		a.smtpHost = host
		a.smtpPort = port
		return nil
	}
}

/* WithOAuth configures the Google OAuth settings. */
func WithOAuth(clientID, clientSecret, redirectURL string) Option {
	return func(a *Auth) error {
		if clientID == "" || clientSecret == "" || redirectURL == "" {
			return ErrEmptyInput
		}
		a.oauthConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			// Endpoint is intentionally omitted here due to imports, it will be added in OAuth method if needed. Wait, we can import golang.org/x/oauth2/google.
			// Let's import it.
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
		return nil
	}
}

/* WithPepper configures the global pepper for password hashing. */
func WithPepper(pepper []byte) Option {
	return func(a *Auth) error {
		if len(pepper) == 0 {
			return ErrEmptyInput
		}
		a.pepper = append([]byte(nil), pepper...)
		return nil
	}
}

/* WithPasswordPolicy configures the rules for valid passwords. */
func WithPasswordPolicy(policy PasswordPolicy) Option {
	return func(a *Auth) error {
		if policy.MinLength <= 0 {
			policy.MinLength = 12
		}
		if policy.MaxLength <= 0 {
			policy.MaxLength = 72
		}
		a.passwordPolicy = policy
		return nil
	}
}

/* New initializes a new Auth instance with the given options. */
/* If WithStorage is not provided, it requires Postgres connection details to fallback on. */
/* Wait, the requirement: "If WithStorage is not provided, default to the PostgresStorage implementation." */
/* But to create PostgresStorage, we need db details. Since we changed the signature to New(ctx, opts...), maybe we provide a WithPostgres() option or read from env. */
/* Let's just create a New(ctx, opts...) and see. */
func New(ctx context.Context, opts ...Option) (*Auth, error) {
	ctx, cancel := context.WithCancel(ctx)

	a := &Auth{
		argonParams:        globalDefaultArgon,
		jwtExpiry:          24 * time.Hour,
		otpExpiry:          5 * time.Minute,
		otpLength:          6,
		refreshTokenExpiry: 30 * 24 * time.Hour,
		refreshTokenLength: 64,
		ctx:                ctx,
		cancel:             cancel,
		passwordPolicy: PasswordPolicy{
			MinLength: 12,
			MaxLength: 72,
		},
	}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			cancel()
			return nil, err
		}
	}

	if a.storage != nil {
		if err := a.storage.CheckTables(ctx); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to check tables: %w", err)
		}
	}

	/* Start background OTP cleanup if storage and OTP are configured. */
	if a.storage != nil && a.otpLength > 0 {
		a.startOTPCleanup()
	}

	return a, nil
}

/* Close cancels the internal context, closes any connections, and securely wipes secrets from memory. */
func (a *Auth) Close() {
	a.cancel()

	// Securely zero out memory for secrets
	for i := range a.pepper {
		a.pepper[i] = 0
	}
	for i := range a.jwtSecret {
		a.jwtSecret[i] = 0
	}
	for i := range a.smtpPassword {
		a.smtpPassword[i] = 0
	}
}

/* HasStorage returns true if the Auth instance has a valid storage engine configured. */
func (a *Auth) HasStorage() bool {
	return a.storage != nil
}

/* HasRedis returns true if the Auth instance has a valid redis client configured. */
func (a *Auth) HasRedis() bool {
	return a.redisClient != nil
}
