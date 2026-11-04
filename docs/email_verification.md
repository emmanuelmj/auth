# Email ownership verification

Email addresses used as usernames must be verified before the account row is created. `RegisterUser` continues to create non-email usernames immediately; for an email address it returns `ErrEmailVerificationRequired` and does not create an account.

This changes the behavior of existing callers that passed email addresses to `RegisterUser`. Move those callers to `StartEmailRegistration`, deliver the emailed code to the user, and call `CompleteEmailRegistration` with the email and code. Non-email usernames retain the previous immediate-registration behavior through `RegisterUser`.

Configure OTP delivery with `WithPepper`, `WithOTP`, and either `WithSMTP` or `WithEmailSender`, then use the two-step registration flow:

```go
if err := client.StartEmailRegistration(ctx, "alice@example.com", password); err != nil {
	return err
}

// Ask the user for the code delivered to their email address.
if err := client.CompleteEmailRegistration(ctx, "alice@example.com", code); err != nil {
	return err
}
```

The pending row contains the password hash and salt, never the plaintext password. The OTP hash and expiry are stored with that pending registration. Successful completion checks and consumes the OTP and creates the verified user in one PostgreSQL transaction. A wrong or expired code does not create an account, and a consumed code cannot be reused.

## Existing accounts

When `CheckTables` adds `email_verified` to an existing `users` table, ordinary existing rows remain `FALSE`; the migration does not change their password hash or salt. The exception is a row with the exact legacy OAuth-managed hash and salt markers. The old OAuth flow wrote that pair only after Google's verified-email claim passed, so those legacy Google-only accounts are migrated to `TRUE` and can continue signing in. The migration can be run repeatedly and applies the same classification each time.

`email_verified` gates email-based registration completion and Google OAuth account linking. Existing local password login remains allowed for unverified accounts, and this migration does not revoke existing JWTs. Applications that require verified email for every authenticated request must enforce that policy separately in their authorization layer.

To verify an existing local account, send an OTP with `SendOTP`, then provide both the account password and supplied code to `VerifyExistingEmail`. The password check prevents someone who can read an email OTP from promoting an existing local account without also knowing its local password.

New Google accounts are marked verified only after Google returns `verified_email: true`. A verified Google identity may sign in to an already verified local account without replacing its password hash or salt.

Custom storage engines remain source-compatible with the base `StorageEngine` interface. To support these flows, they must also implement `EmailVerificationStorage` and `OAuthAccountStorage`; the library fails closed for the corresponding operation when those optional capabilities are missing.

## Rate limiting verification attempts

`CompleteEmailRegistration` and `VerifyExistingEmail` do not apply a rate limit themselves. A six-digit OTP has one million possible values, so unrestricted guesses can eventually find a valid code before it expires. Applications must rate-limit these calls at the HTTP/API boundary. For example, use the library's limiter before calling either method:

Create the in-memory limiter once when the application starts, not once per request:

```go
limiter, err := auth.NewRateLimiter(auth.RateLimiterConfig{
	MaxRequests: 5,
	Window:     time.Minute,
})
if err != nil {
	return err
}
// Call limiter.Stop() when the application shuts down.
```

Before either verification method, enforce limits independently for the normalized email and caller IP:

```go
for _, key := range []string{"verify-email:email:" + normalizedEmail, "verify-email:ip:" + clientIP} {
	if err := limiter.Allow(ctx, key); err != nil {
		// Return HTTP 429 without calling CompleteEmailRegistration or VerifyExistingEmail.
		return err
	}
}
```

The in-memory `RateLimiter` is local to one process, so deployments with multiple application instances need a shared limiter such as the library's Redis-backed limiter or an equivalent API gateway policy. Apply limits to both the email address and the caller's network identity, and avoid exposing whether an address has an account in responses.

## Expired pending registrations

Expired pending-registration rows cannot be completed, but the library currently does not delete them automatically. Applications should periodically remove rows whose `expires_at` is in the past (for example, with a scheduled maintenance task running `DELETE FROM pending_email_registrations WHERE expires_at <= CURRENT_TIMESTAMP`). This only removes expired pending data and does not affect users or valid registrations.
