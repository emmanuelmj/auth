# Auth

Auth. Works with Postgres. Supports multiple auth methods (Password, JWT, OTP, Google OAuth 2.0), spaces, roles, permissions. Integrates with any API library.

## Installation
`go get github.com/GCET-Open-Source-Foundation/auth`

## Usage

* **`auth.Init(ctx, port, dbUser, dbPass, dbName, host)`** - Sets up the library. Connects to Postgres, prepares internal state, and verifies database schema. Must be called before doing anything else.
* **`auth.JWTInit(secret)`** - Initializes the JWT signing key. Required if you intend to use stateless authentication.
* **`auth.GoogleOAuthInit(clientID, clientSecret, redirectURL)`** - Initializes the Google OAuth 2.0 client configuration.
* **`auth.GetGoogleLoginURL(state)`** - Generates the Google OAuth consent screen URL with your state parameter.
* **`auth.HandleGoogleCallback(ctx, code)`** - Exchanges a Google callback code for user profile info.
* **`auth.SMTPInit(email, password, host, port)`** - Configures the SMTP client. Required for sending OTP emails.
* **`auth.CreateSpace(name, authority)`** - Creates a new space with the given name. Authority determines control level for the space. Fails if space already exists or Init() was not called.
* **`auth.DeleteSpace(name)`** - Deletes the space with the specified name. Removes all associated permissions. Fails if space does not exist.
* **`auth.CreatePermissions(username, spaceName, role)`** - Assigns a role to a user in a specific space. Roles define what the user can do in that space.
* **`auth.DeletePermission(username, spaceName, role)`** - Removes a user's role in a specific space. After this, the user loses access according to that role.
* You can also handle users with **`auth.RegisterUser()`**, **`auth.LoginUser()`**, **`auth.LoginJWT()`**, **`auth.LoginWithGoogle()`** and **`auth.DeleteUser()`**.
* For roles, use **`auth.CreateRole()`** and **`auth.DeleteRole()`**.
