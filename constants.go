package auth

const (
	/* OAuthManagedHash is the placeholder password hash used for users */
	/* who authenticate exclusively via an external OAuth provider. */
	OAuthManagedHash = "OAUTH_MANAGED"

	/* OAuthManagedSalt is the placeholder password salt used for users */
	/* who authenticate exclusively via an external OAuth provider. */
	OAuthManagedSalt = "OAUTH_MANAGED_SALT_16B"
)
