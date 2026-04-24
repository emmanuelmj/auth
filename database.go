package auth

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
Creates the needed schema from scratch for prompted table.
Expects table to not be present at all.
*/
func (a *Auth) createSpaces(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS spaces (
	spaceName TEXT PRIMARY KEY,
	authority INTEGER NOT NULL
	 )`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating spaces table: %w", err)
	}
	log.Println("Spaces table created successfully (or already exists).")
	return nil
}

func (a *Auth) createUsers(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	password_hash TEXT,
	 salt TEXT,
	auth_provider TEXT NOT NULL DEFAULT 'local',
	google_id TEXT UNIQUE
	)`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating users table: %w", err)
	}
	log.Println("Users table created successfully (or already exists).")
	return nil
}

func (a *Auth) createRoles(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS roles (
	role TEXT PRIMARY KEY
	)`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating roles table: %w", err)
	}
	log.Println("Roles table created successfully (or already exists).")
	return nil
}

func (a *Auth) createPermissions(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS permissions (
	user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	spaceName TEXT NOT NULL REFERENCES spaces(spaceName) ON DELETE CASCADE,
	role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
	PRIMARY KEY (user_id, spaceName, role)
	)`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating permissions table: %w", err)
	}
	log.Println("Permissions table created successfully (or already exists).")
	return nil
}

func (a *Auth) createOTPs(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS otps (
		email TEXT PRIMARY KEY,
		code TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL
	)`
	_, err := a.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("error creating otps table: %w", err)
	}
	log.Println("OTPs table created successfully (or already exists).")
	return nil
}

/*
These functions now return 'error' instead of calling log.Fatal()
*/
func (a *Auth) checkSpaces(ctx context.Context) error {
	query := `
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'spaces'
            ORDER BY ordinal_position;
      `
	rows, err := a.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query spaces schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dataType, isNullable string
		if err := rows.Scan(&name, &dataType, &isNullable); err != nil {
			return fmt.Errorf("failed to scan spaces schema: %w", err)
		}
		columns[name] = struct {
			dataType   string
			isNullable string
		}{dataType, isNullable}
	}

	expected := map[string]string{
		"spaceName": "text",
		"authority": "integer",
	}

	for col, typ := range expected {
		if c, ok := columns[col]; !ok || c.dataType != typ {
			return fmt.Errorf("spaces table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	log.Println("Spaces table schema is correct.")
	return nil
}

func (a *Auth) checkUsers(ctx context.Context) error {
	query := `
	SELECT column_name, data_type, is_nullable, column_default
	FROM information_schema.columns
	WHERE table_name = 'users'
	ORDER BY ordinal_position;
      `
	rows, err := a.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query users schema: %w", err)
	}
	defer rows.Close()

	type columnInfo struct {
		dataType      string
		isNullable    string
		columnDefault string
	}
	columns := map[string]columnInfo{}
	for rows.Next() {
		var name, dataType, isNullable string
		var columnDefault *string
		if err := rows.Scan(&name, &dataType, &isNullable, &columnDefault); err != nil {
			return fmt.Errorf("failed to scan users schema: %w", err)
		}
		colDefault := ""
		if columnDefault != nil {
			colDefault = *columnDefault
		}
		columns[name] = columnInfo{
			dataType:      dataType,
			isNullable:    isNullable,
			columnDefault: colDefault,
		}
	}

	expected := map[string]string{
		"user_id":       "text",
		"password_hash": "text",
		"salt":          "text",
		"auth_provider": "text",
		"google_id":     "text",
	}

	for col, typ := range expected {
		if c, ok := columns[col]; !ok || c.dataType != typ {
			return fmt.Errorf("users table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	if columns["password_hash"].isNullable != "YES" {
		return fmt.Errorf("users table schema mismatch for column 'password_hash': expected nullable column for oauth users")
	}
	if !strings.Contains(columns["auth_provider"].columnDefault, "'local'") {
		return fmt.Errorf("users table schema mismatch for column 'auth_provider': expected default 'local', got %s", columns["auth_provider"].columnDefault)
	}

	log.Println("Users table schema is correct.")
	return nil
}

func (a *Auth) migrateUsersOAuthSchema(ctx context.Context) error {
	migrationQueries := []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'local'",
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT",
		"ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL",
		"ALTER TABLE users ALTER COLUMN salt DROP NOT NULL",
		"CREATE UNIQUE INDEX IF NOT EXISTS users_google_id_unique_idx ON users (google_id) WHERE google_id IS NOT NULL",
	}

	for _, query := range migrationQueries {
		if _, err := a.Conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("failed oauth schema migration for users table: %w", err)
		}
	}

	return nil
}

func (a *Auth) checkRoles(ctx context.Context) error {
	query := `
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'roles'
            ORDER BY ordinal_position;
	      `
	rows, err := a.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query roles schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("failed to scan roles schema: %w", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"role": "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			return fmt.Errorf("roles table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	log.Println("Roles table schema is correct.")
	return nil
}

func (a *Auth) checkPermissions(ctx context.Context) error {
	query := `
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'permissions'
            ORDER BY ordinal_position;
      `
	rows, err := a.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query permissions schema: %w", err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			return fmt.Errorf("failed to scan permissions schema: %w", err)
		}
		columns[name] = dataType
	}

	expected := map[string]string{
		"user_id":   "text",
		"spaceName": "text",
		"role":      "text",
	}

	for col, typ := range expected {
		if t, ok := columns[col]; !ok || t != typ {
			return fmt.Errorf("permissions table schema mismatch for column '%s': expected %s, got %s", col, typ, t)
		}
	}

	log.Println("Permissions table schema is correct.")
	return nil
}

func (a *Auth) checkOTPs(ctx context.Context) error {
	query := `
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'otps'
            ORDER BY ordinal_position;
      `
	rows, err := a.Conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query otps schema: %w", err)
	}
	defer rows.Close()

	/* We'll map the columns we find to verify them */
	columns := map[string]struct {
		dataType   string
		isNullable string
	}{}
	for rows.Next() {
		var name, dataType, isNullable string
		if err := rows.Scan(&name, &dataType, &isNullable); err != nil {
			return fmt.Errorf("failed to scan otps schema: %w", err)
		}
		columns[name] = struct {
			dataType   string
			isNullable string
		}{dataType, isNullable}
	}

	/* Define what we expect
	Note: In Postgres, TIMESTAMP WITHOUT TIME ZONE usually shows as 'timestamp without time zone'
	Depending on your specific Postgres setup, it might just be 'timestamp'.
	The library seems to check simple types. Let's assume standard text/timestamp. */
	expected := map[string]string{
		"email":      "text",
		"code":       "text",
		"expires_at": "timestamp without time zone", // standard postgres timestamp type
	}

	for col, typ := range expected {
		if c, ok := columns[col]; !ok || c.dataType != typ {
			/* If validation fails, we return an error */
			return fmt.Errorf("otps table schema mismatch for column '%s': expected %s, got %s", col, typ, c.dataType)
		}
	}

	log.Println("OTPs table schema is correct.")
	return nil
}

/*
Checks if the table exists or not and returns the output in boolean
*/
func (a *Auth) tableExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables  
			WHERE table_schema = 'public'
			AND table_name = $1
	)`
	err := a.Conn.QueryRow(ctx, query, table).Scan(&exists)
	return exists, err
}

/*
Systematically checks all tables and returns an error if any check fails.
*/
func (a *Auth) checkTables(ctx context.Context) error {
	var check bool = false
	var err error = nil

	check, err = a.tableExists(ctx, "spaces")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.checkSpaces(ctx); err != nil {
				return err
			}
		} else {
			if err = a.createSpaces(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.tableExists(ctx, "users")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.migrateUsersOAuthSchema(ctx); err != nil {
				return err
			}
			if err = a.checkUsers(ctx); err != nil {
				return err
			}
		} else {
			if err = a.createUsers(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.tableExists(ctx, "roles")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.checkRoles(ctx); err != nil {
				return err
			}
		} else {
			if err = a.createRoles(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.tableExists(ctx, "permissions")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.checkPermissions(ctx); err != nil {
				return err
			}
		} else {
			if err = a.createPermissions(ctx); err != nil {
				return err
			}
		}
	}

	check, err = a.tableExists(ctx, "otps")
	if err != nil {
		return err
	} else {
		if check {
			if err = a.checkOTPs(ctx); err != nil {
				return err
			}
		} else {
			if err = a.createOTPs(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

/*
Wrapper function around jackc/pgx/v5 pgx.Conn().
Returns a *pgx.Conn structure.
*/

func dbConnect(ctx context.Context, details *dbDetails) (*pgxpool.Pool, error) {
	/*
		The password may contain multiple special characters,
		therefore it is primordial to use, url.URL here.
	*/
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(details.username, details.password),
		Host:   fmt.Sprintf("%s:%d", details.host, details.port),
		Path:   details.databaseName,
	}

	urlStr := u.String()

	pool, err := pgxpool.New(ctx, urlStr)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create Connection pool: %w\nPlease configure Postgres correctly",
			err,
		)
	}

	if err := pool.QueryRow(ctx, "SELECT 1").Scan(new(int)); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to Connect to Postgres: %w", err)
	}

	log.Println("DB Connection pool established")

	return pool, nil
}
