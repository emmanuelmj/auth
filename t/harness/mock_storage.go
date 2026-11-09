package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
)

type userRecord struct {
	hash string
	salt string
}

type spaceRecord struct {
	authority int
}

type otpRecord struct {
	code      string
	expiresAt time.Time
}

type refreshRecord struct {
	userID    string
	expiresAt time.Time
	revoked   bool
	createdAt time.Time
}

type permKey struct {
	userID    string
	spaceName string
	role      string
}

/* MockStorage is a fully in-memory, thread-safe implementation of auth.StorageEngine with fault injection. */
type MockStorage struct {
	mu            sync.RWMutex
	users         map[string]userRecord
	spaces        map[string]spaceRecord
	roles         map[string]bool
	permissions   map[permKey]bool
	otps          map[string]otpRecord
	refreshTokens map[string]refreshRecord

	// Fault injection hooks
	CheckTablesErr        error
	InsertUserErr         error
	UpdateUserPasswordErr error
	DeleteUserErr         error
	UserExistsErr         error
	GetUserErr            error
	ListUsersErr          error
	UpsertOAuthUserErr    error
	InsertSpaceErr        error
	DeleteSpaceErr        error
	InsertRoleErr         error
	DeleteRoleErr         error
	InsertPermissionErr   error
	CheckPermissionErr    error
	DeletePermissionErr   error
	InsertOTPErr          error
	GetOTPErr             error
	DeleteOTPErr          error
	ListActiveOTPsErr     error
	CleanupOTPErr         error
	InsertRefreshErr      error
	GetRefreshErr         error
	RevokeRefreshErr      error
	RevokeAllRefreshErr   error
	CleanupRefreshErr     error
	CloseErr              error
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		users:         make(map[string]userRecord),
		spaces:        make(map[string]spaceRecord),
		roles:         make(map[string]bool),
		permissions:   make(map[permKey]bool),
		otps:          make(map[string]otpRecord),
		refreshTokens: make(map[string]refreshRecord),
	}
}

func (m *MockStorage) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = make(map[string]userRecord)
	m.spaces = make(map[string]spaceRecord)
	m.roles = make(map[string]bool)
	m.permissions = make(map[permKey]bool)
	m.otps = make(map[string]otpRecord)
	m.refreshTokens = make(map[string]refreshRecord)

	m.CheckTablesErr = nil
	m.InsertUserErr = nil
	m.UpdateUserPasswordErr = nil
	m.DeleteUserErr = nil
	m.UserExistsErr = nil
	m.GetUserErr = nil
	m.ListUsersErr = nil
	m.UpsertOAuthUserErr = nil
	m.InsertSpaceErr = nil
	m.DeleteSpaceErr = nil
	m.InsertRoleErr = nil
	m.DeleteRoleErr = nil
	m.InsertPermissionErr = nil
	m.CheckPermissionErr = nil
	m.DeletePermissionErr = nil
	m.InsertOTPErr = nil
	m.GetOTPErr = nil
	m.DeleteOTPErr = nil
	m.ListActiveOTPsErr = nil
	m.CleanupOTPErr = nil
	m.InsertRefreshErr = nil
	m.GetRefreshErr = nil
	m.RevokeRefreshErr = nil
	m.RevokeAllRefreshErr = nil
	m.CleanupRefreshErr = nil
	m.CloseErr = nil
}

func (m *MockStorage) CheckTables(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.CheckTablesErr
}

/* Users */

func (m *MockStorage) InsertUser(ctx context.Context, username, hash, salt string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertUserErr != nil {
		return m.InsertUserErr
	}
	if _, exists := m.users[username]; exists {
		return errors.New("user already exists")
	}
	m.users[username] = userRecord{hash: hash, salt: salt}
	return nil
}

func (m *MockStorage) UpdateUserPassword(ctx context.Context, username, hash, salt string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpdateUserPasswordErr != nil {
		return 0, m.UpdateUserPasswordErr
	}
	if _, exists := m.users[username]; !exists {
		return 0, nil
	}
	m.users[username] = userRecord{hash: hash, salt: salt}
	return 1, nil
}

func (m *MockStorage) DeleteUser(ctx context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteUserErr != nil {
		return m.DeleteUserErr
	}
	delete(m.users, username)

	// Cascade delete permissions
	for k := range m.permissions {
		if k.userID == username {
			delete(m.permissions, k)
		}
	}
	// Cascade delete refresh tokens
	for token, rec := range m.refreshTokens {
		if rec.userID == username {
			delete(m.refreshTokens, token)
		}
	}
	return nil
}

func (m *MockStorage) UserExists(ctx context.Context, username string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.UserExistsErr != nil {
		return false, m.UserExistsErr
	}
	_, exists := m.users[username]
	return exists, nil
}

func (m *MockStorage) GetUserHashAndSalt(ctx context.Context, username string) (string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetUserErr != nil {
		return "", "", m.GetUserErr
	}
	u, exists := m.users[username]
	if !exists {
		return "", "", auth.ErrUserNotFound
	}
	return u.hash, u.salt, nil
}

func (m *MockStorage) ListUsers(ctx context.Context, limit, offset int) ([]auth.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ListUsersErr != nil {
		return nil, m.ListUsersErr
	}

	keys := make([]string, 0, len(m.users))
	for k := range m.users {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if offset < 0 {
		offset = 0
	}
	if offset >= len(keys) {
		return []auth.User{}, nil
	}

	end := offset + limit
	if limit <= 0 || end > len(keys) {
		end = len(keys)
	}

	res := make([]auth.User, 0, end-offset)
	for _, k := range keys[offset:end] {
		res = append(res, auth.User{UserID: k})
	}
	return res, nil
}

func (m *MockStorage) UpsertOAuthUser(ctx context.Context, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.UpsertOAuthUserErr != nil {
		return m.UpsertOAuthUserErr
	}
	if _, exists := m.users[email]; !exists {
		m.users[email] = userRecord{
			hash: auth.OAuthManagedHash,
			salt: auth.OAuthManagedSalt,
		}
	}
	return nil
}

/* Spaces */

func (m *MockStorage) InsertSpace(ctx context.Context, name string, authority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertSpaceErr != nil {
		return m.InsertSpaceErr
	}
	if _, exists := m.spaces[name]; exists {
		return errors.New("space already exists")
	}
	m.spaces[name] = spaceRecord{authority: authority}
	return nil
}

func (m *MockStorage) DeleteSpace(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteSpaceErr != nil {
		return m.DeleteSpaceErr
	}
	delete(m.spaces, name)
	for k := range m.permissions {
		if k.spaceName == name {
			delete(m.permissions, k)
		}
	}
	return nil
}

/* Roles */

func (m *MockStorage) InsertRole(ctx context.Context, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertRoleErr != nil {
		return m.InsertRoleErr
	}
	if m.roles[role] {
		return errors.New("role already exists")
	}
	m.roles[role] = true
	return nil
}

func (m *MockStorage) DeleteRole(ctx context.Context, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteRoleErr != nil {
		return m.DeleteRoleErr
	}
	delete(m.roles, role)
	for k := range m.permissions {
		if k.role == role {
			delete(m.permissions, k)
		}
	}
	return nil
}

/* Permissions */

func (m *MockStorage) InsertPermission(ctx context.Context, username, spaceName, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertPermissionErr != nil {
		return m.InsertPermissionErr
	}
	if _, exists := m.users[username]; !exists {
		return errors.New("foreign key violation: user not found")
	}
	if _, exists := m.spaces[spaceName]; !exists {
		return errors.New("foreign key violation: space not found")
	}
	if !m.roles[role] {
		return errors.New("foreign key violation: role not found")
	}

	key := permKey{userID: username, spaceName: spaceName, role: role}
	if m.permissions[key] {
		return errors.New("permission already exists")
	}
	m.permissions[key] = true
	return nil
}

func (m *MockStorage) CheckPermissionExists(ctx context.Context, username, spaceName, role string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.CheckPermissionErr != nil {
		return false, m.CheckPermissionErr
	}
	key := permKey{userID: username, spaceName: spaceName, role: role}
	return m.permissions[key], nil
}

func (m *MockStorage) DeletePermission(ctx context.Context, username, spaceName, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeletePermissionErr != nil {
		return m.DeletePermissionErr
	}
	key := permKey{userID: username, spaceName: spaceName, role: role}
	delete(m.permissions, key)
	return nil
}

/* OTP */

func (m *MockStorage) InsertOTP(ctx context.Context, email, code string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertOTPErr != nil {
		return m.InsertOTPErr
	}
	m.otps[email] = otpRecord{code: code, expiresAt: expiresAt.UTC()}
	return nil
}

func (m *MockStorage) GetOTP(ctx context.Context, email string) (string, time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetOTPErr != nil {
		return "", time.Time{}, m.GetOTPErr
	}
	rec, exists := m.otps[email]
	if !exists {
		return "", time.Time{}, auth.ErrOTPNotFound
	}
	return rec.code, rec.expiresAt.UTC(), nil
}

func (m *MockStorage) DeleteOTP(ctx context.Context, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.DeleteOTPErr != nil {
		return m.DeleteOTPErr
	}
	delete(m.otps, email)
	return nil
}

func (m *MockStorage) ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ListActiveOTPsErr != nil {
		return nil, m.ListActiveOTPsErr
	}

	now := time.Now().UTC()
	var active []string
	for email, rec := range m.otps {
		if rec.expiresAt.After(now) {
			active = append(active, email)
		}
	}
	sort.Strings(active)

	if offset < 0 {
		offset = 0
	}
	if offset >= len(active) {
		return []string{}, nil
	}
	end := offset + limit
	if limit <= 0 || end > len(active) {
		end = len(active)
	}
	return active[offset:end], nil
}

func (m *MockStorage) CleanupExpiredOTPs(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CleanupOTPErr != nil {
		return m.CleanupOTPErr
	}
	now := time.Now().UTC()
	for email, rec := range m.otps {
		if !rec.expiresAt.After(now) {
			delete(m.otps, email)
		}
	}
	return nil
}

/* Refresh Tokens */

func (m *MockStorage) InsertRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.InsertRefreshErr != nil {
		return m.InsertRefreshErr
	}
	if _, exists := m.users[userID]; !exists {
		return errors.New("foreign key violation: user does not exist")
	}
	m.refreshTokens[token] = refreshRecord{
		userID:    userID,
		expiresAt: expiresAt.UTC(),
		revoked:   false,
		createdAt: time.Now().UTC(),
	}
	return nil
}

func (m *MockStorage) GetRefreshToken(ctx context.Context, token string) (string, time.Time, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.GetRefreshErr != nil {
		return "", time.Time{}, false, m.GetRefreshErr
	}
	rec, exists := m.refreshTokens[token]
	if !exists {
		return "", time.Time{}, false, auth.ErrRefreshTokenInvalid
	}
	return rec.userID, rec.expiresAt.UTC(), rec.revoked, nil
}

func (m *MockStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RevokeRefreshErr != nil {
		return m.RevokeRefreshErr
	}
	rec, exists := m.refreshTokens[token]
	if !exists {
		return auth.ErrRefreshTokenInvalid
	}
	rec.revoked = true
	m.refreshTokens[token] = rec
	return nil
}

func (m *MockStorage) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RevokeAllRefreshErr != nil {
		return m.RevokeAllRefreshErr
	}
	for token, rec := range m.refreshTokens {
		if rec.userID == userID {
			rec.revoked = true
			m.refreshTokens[token] = rec
		}
	}
	return nil
}

func (m *MockStorage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CleanupRefreshErr != nil {
		return m.CleanupRefreshErr
	}
	now := time.Now().UTC()
	for token, rec := range m.refreshTokens {
		if !rec.expiresAt.After(now) {
			delete(m.refreshTokens, token)
		}
	}
	return nil
}

func (m *MockStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CloseErr
}
