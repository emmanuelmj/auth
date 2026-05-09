package auth

import "context"

/* CreateRole registers a new role in the system. */
func (a *Auth) CreateRole(ctx context.Context, name string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.InsertRole(ctx, name); err != nil {
		return err
	}

	return nil
}

/* DeleteRole removes an existing role from the system. */
func (a *Auth) DeleteRole(ctx context.Context, name string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.DeleteRole(ctx, name); err != nil {
		return err
	}

	return nil
}
