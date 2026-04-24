package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

var (
	googleOAuthConfig oauth2.Config
	oauthConfigMu     sync.RWMutex
)

func GoogleOAuthInit(clientID, clientSecret, redirectURL string) {
	oauthConfigMu.Lock()
	defer oauthConfigMu.Unlock()

	googleOAuthConfig = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"userinfo.email",
			"userinfo.profile",
		},
	}
}

func GetGoogleLoginURL(state string) string {
	oauthConfigMu.RLock()
	defer oauthConfigMu.RUnlock()

	return googleOAuthConfig.AuthCodeURL(state)
}

func HandleGoogleCallback(ctx context.Context, code string) (*GoogleUser, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	if code == "" {
		return nil, ErrEmptyInput
	}

	oauthConfigMu.RLock()
	config := googleOAuthConfig
	oauthConfigMu.RUnlock()

	if config.ClientID == "" || config.ClientSecret == "" || config.RedirectURL == "" {
		return nil, ErrNotInitialized
	}

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange google auth code: %w", err)
	}

	client := config.Client(ctx, token)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create google userinfo request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google user profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("google userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var gUser GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&gUser); err != nil {
		return nil, fmt.Errorf("failed to decode google user profile: %w", err)
	}
	if gUser.ID == "" || gUser.Email == "" {
		return nil, fmt.Errorf("%w: missing google user identity fields", ErrInvalidInput)
	}

	return &gUser, nil
}
