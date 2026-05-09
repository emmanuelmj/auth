package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GCET-Open-Source-Foundation/auth/email"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

/* EmailSender defines the interface for sending emails. */
type EmailSender interface {
	SendEmail(ctx context.Context, to, subject, body string) error
}

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
	jwtSecret          []byte
	jwtExpiry          time.Duration
	otpExpiry          time.Duration
	otpLength          int
	emailSender        EmailSender
	refreshTokenExpiry time.Duration
	refreshTokenLength int
	otpEnabled         bool
	cancel             context.CancelFunc
	oauthConfig        *oauth2.Config
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

		/* Attempt to load the rate limit script */
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sha, err := client.ScriptLoad(ctx, rateLimitScript).Result()
		if err != nil {
			return fmt.Errorf("failed to load redis rate limit script: %w", err)
		}
		a.rateLimitSHA = sha
		return nil
	}
}

/* WithRefreshToken sets the duration for which a refresh token is valid and its length. */
func WithRefreshToken(expiry time.Duration, length int) Option {
	return func(a *Auth) error {
		if expiry <= 0 {
			return ErrInvalidInput
		}
		a.refreshTokenExpiry = expiry
		if length <= 0 {
			length = 32
		}
		a.refreshTokenLength = length
		return nil
	}
}

/* WithOTP configures the OTP length and expiration time. */
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
		a.otpEnabled = true
		return nil
	}
}

/*
	WithJWT configures the JWT signing secret and expiration time.

If expiry is 0 or negative the pre-seeded default of 24 hours is kept.
*/
func WithJWT(secret []byte, expiry time.Duration) Option {
	return func(a *Auth) error {
		if len(secret) == 0 {
			return ErrEmptyInput
		}
		a.jwtSecret = append([]byte(nil), secret...) /* defensive copy */
		if expiry > 0 {
			a.jwtExpiry = expiry
		}
		/* expiry == 0 → keep the 24 h default already set in New(). */
		return nil
	}
}

/* WithEmailSender configures the Auth instance to use a custom EmailSender. */
func WithEmailSender(sender EmailSender) Option {
	return func(a *Auth) error {
		if sender == nil {
			return ErrEmptyInput
		}
		a.emailSender = sender
		return nil
	}
}

type smtpEmailSender struct {
	email    string
	password []byte
	host     string
	port     string
}

func (s *smtpEmailSender) SendEmail(ctx context.Context, to, subject, body string) error {
	return email.Send(s.host, s.port, s.email, string(s.password), to, subject, body)
}

/* WithSMTP configures the SMTP server details for sending emails (e.g., OTP). */
func WithSMTP(email, password, host, port string) Option {
	return func(a *Auth) error {
		if email == "" || password == "" || host == "" || port == "" {
			return ErrEmptyInput
		}
		a.emailSender = &smtpEmailSender{
			email:    email,
			password: []byte(password),
			host:     host,
			port:     port,
		}
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
			/* Hardcode Google OAuth endpoints directly to avoid pulling in the
			   golang.org/x/oauth2/google sub-package as a mandatory dependency. */
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

/*
New initializes an Auth instance and applies the provided Option functions in
order. If any option returns an error the constructor cancels its internal
context and propagates the error to the caller.

WithStorage must be provided to enable any database-backed operation
(login, OTP, refresh tokens). The constructor calls CheckTables to ensure the
required schema exists before returning. If WithOTP is provided alongside
WithStorage, a background goroutine is started to periodically purge expired
OTP rows.
*/
func New(ctx context.Context, opts ...Option) (*Auth, error) {
	ctx, cancel := context.WithCancel(ctx)

	a := &Auth{
		argonParams:        globalDefaultArgon,
		jwtExpiry:          24 * time.Hour,
		otpExpiry:          5 * time.Minute,
		otpLength:          6,
		refreshTokenExpiry: 30 * 24 * time.Hour,
		refreshTokenLength: 32,
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

	/* Guard: pepper is mandatory when OTP is explicitly enabled. */
	if a.otpEnabled && len(a.pepper) == 0 {
		cancel()
		return nil, errors.New("OTP requires a pepper: configure WithPepper before WithOTP")
	}

	if a.storage != nil {
		if err := a.storage.CheckTables(ctx); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to check tables: %w", err)
		}
	}

	/* Start background OTP cleanup if storage and OTP are configured. */
	if a.storage != nil && a.otpEnabled {
		a.startOTPCleanup(ctx)
	}

	return a, nil
}

/* Close cancels the internal context, closes any connections, and securely wipes secrets from memory. */
func (a *Auth) Close() {
	a.cancel()

	if a.storage != nil {
		a.storage.Close()
	}
	if a.redisClient != nil {
		a.redisClient.Close()
	}

	/* Securely zero out memory for secrets */
	for i := range a.pepper {
		a.pepper[i] = 0
	}
	for i := range a.jwtSecret {
		a.jwtSecret[i] = 0
	}
	if sender, ok := a.emailSender.(*smtpEmailSender); ok {
		for i := range sender.password {
			sender.password[i] = 0
		}
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
