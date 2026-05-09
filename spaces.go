package auth

import "context"

/* CreateSpace initializes a new organizational space with a specific authority level. */
func (a *Auth) CreateSpace(ctx context.Context, name string, authority int) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.InsertSpace(ctx, name, authority); err != nil {
		return err
	}

	return nil
}

/* DeleteSpace removes an existing organizational space and all its associated data. */
func (a *Auth) DeleteSpace(ctx context.Context, name string) error {
	if a.storage == nil {
		return ErrNotInitialized
	}

	if err := a.storage.DeleteSpace(ctx, name); err != nil {
		return err
	}

	return nil
}
