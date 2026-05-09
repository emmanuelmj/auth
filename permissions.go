package auth

import "context"

/* CreatePermissions assigns a role to a user within a specific space. */
func (a *Auth) CreatePermissions(ctx context.Context, username, spaceName, role string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.InsertPermission(ctx, username, spaceName, role); err != nil {
		return err
	}

	return nil
}

/* CheckPermissions verifies if a user has a specific role within a space. */
func (a *Auth) CheckPermissions(ctx context.Context, username, spaceName, role string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	hasPerm, err := a.storage.CheckPermissionExists(ctx, username, spaceName, role)
	if err != nil {
		return ErrDatabaseUnavailable
	}

	if !hasPerm {
		return ErrInvalidCredentials
	}

	return nil
}

/* DeletePermission removes a specific role assignment from a user in a space. */
func (a *Auth) DeletePermission(ctx context.Context, username, spaceName, role string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.DeletePermission(ctx, username, spaceName, role); err != nil {
		return err
	}

	return nil
}
