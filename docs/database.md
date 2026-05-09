# database.go → storage.go + postgres/postgres.go

The database layer has been decoupled into two parts:

## storage.go (core package)

`storage.go` defines the `StorageEngine` interface — the contract that any storage backend must implement. It lives in the root `auth` package and has **no database-driver dependencies**.

```go
type StorageEngine interface {
    CheckTables(ctx context.Context) error

    // Users
    InsertUser(ctx context.Context, username, hash, salt string) error
    GetUserHashAndSalt(ctx context.Context, username string) (hash, salt string, err error)
    // ... and more
}
```

The core `Auth` struct only interacts with this interface. This means you can swap PostgreSQL for any other backend (MySQL, SQLite, in-memory, etc.) by implementing the `StorageEngine` interface.

## postgres/postgres.go (sub-package)

The `postgres` sub-package provides the default PostgreSQL implementation via `PostgresStorage`. Import it only when you need a Postgres backend:

```go
import (
    auth "github.com/GCET-Open-Source-Foundation/auth"
    authpg "github.com/GCET-Open-Source-Foundation/auth/postgres"
)

storage, err := authpg.NewPostgresStorage(ctx, 5432, "user", "pass", "dbname", "localhost")
a, err := auth.New(ctx, auth.WithStorage(storage))
```

### Key design decisions

- **Error translation**: The `PostgresStorage` translates driver-specific errors (e.g., `pgx.ErrNoRows`) into generic library errors (e.g., `auth.ErrUserNotFound`) at the storage boundary, so the core package never needs to know about pgx.
- **Schema management**: `CheckTables()` creates all required tables using `CREATE TABLE IF NOT EXISTS`.
- **Connection pooling**: Uses `pgxpool` for connection pooling and verifies connectivity on startup with a `SELECT 1` health check.

### Schema

The following tables are created by `CheckTables()`:

| Table             | Purpose                       |
|-------------------|-------------------------------|
| `spaces`          | Organizational spaces         |
| `users`           | User credentials              |
| `roles`           | Role definitions              |
| `permissions`     | User-space-role assignments   |
| `otps`            | One-time passwords            |
| `refresh_tokens`  | Opaque refresh tokens         |