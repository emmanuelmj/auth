package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type rewriteUserInfoTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t *rewriteUserInfoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	if req.URL.Host == "www.googleapis.com" && req.URL.Path == "/oauth2/v2/userinfo" {
		clone := req.Clone(req.Context())
		newURL := *clone.URL
		newURL.Scheme = t.target.Scheme
		newURL.Host = t.target.Host
		newURL.Path = "/oauth2/v2/userinfo"
		clone.URL = &newURL
		return base.RoundTrip(clone)
	}

	return base.RoundTrip(req)
}

func resetGoogleOAuthConfigForTest() {
	oauthConfigMu.Lock()
	defer oauthConfigMu.Unlock()
	googleOAuthConfig = oauth2.Config{}
}

func setGoogleTokenEndpointForTest(tokenURL string) {
	oauthConfigMu.Lock()
	defer oauthConfigMu.Unlock()
	googleOAuthConfig.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://accounts.google.com/o/oauth2/auth",
		TokenURL: tokenURL,
	}
}

func TestGetGoogleLoginURLIncludesStateAndScopes(t *testing.T) {
	t.Cleanup(resetGoogleOAuthConfigForTest)

	GoogleOAuthInit("test-client", "test-secret", "http://localhost:8080/callback")
	loginURL := GetGoogleLoginURL("state-123")

	if loginURL == "" {
		t.Fatal("expected non-empty login URL")
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("failed to parse login URL: %v", err)
	}

	if got := parsed.Query().Get("state"); got != "state-123" {
		t.Fatalf("unexpected state: got %q", got)
	}

	scope := parsed.Query().Get("scope")
	if !strings.Contains(scope, "userinfo.email") || !strings.Contains(scope, "userinfo.profile") {
		t.Fatalf("unexpected scopes in URL: %q", scope)
	}
}

func TestHandleGoogleCallbackValidation(t *testing.T) {
	t.Cleanup(resetGoogleOAuthConfigForTest)

	_, err := HandleGoogleCallback(nil, "code")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for nil context, got: %v", err)
	}

	_, err = HandleGoogleCallback(context.Background(), "")
	if !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("expected ErrEmptyInput for empty code, got: %v", err)
	}

	_, err = HandleGoogleCallback(context.Background(), "code")
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized without oauth config, got: %v", err)
	}
}

func TestHandleGoogleCallbackScenarios(t *testing.T) {
	testCases := []struct {
		name            string
		tokenStatus     int
		tokenBody       string
		userInfoStatus  int
		userInfoBody    string
		expectErr       bool
		expectErrSubstr string
		expectUser      *GoogleUser
	}{
		{
			name:           "success",
			tokenStatus:    http.StatusOK,
			tokenBody:      `{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`,
			userInfoStatus: http.StatusOK,
			userInfoBody:   `{"id":"g-1","email":"dev@example.com","name":"Dev User"}`,
			expectUser:     &GoogleUser{ID: "g-1", Email: "dev@example.com", Name: "Dev User"},
		},
		{
			name:            "token exchange failure",
			tokenStatus:     http.StatusBadRequest,
			tokenBody:       `{"error":"invalid_grant"}`,
			expectErr:       true,
			expectErrSubstr: "failed to exchange google auth code",
		},
		{
			name:            "userinfo non-200",
			tokenStatus:     http.StatusOK,
			tokenBody:       `{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`,
			userInfoStatus:  http.StatusInternalServerError,
			userInfoBody:    "upstream error",
			expectErr:       true,
			expectErrSubstr: "google userinfo request failed with status 500",
		},
		{
			name:            "userinfo invalid json",
			tokenStatus:     http.StatusOK,
			tokenBody:       `{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`,
			userInfoStatus:  http.StatusOK,
			userInfoBody:    "not-json",
			expectErr:       true,
			expectErrSubstr: "failed to decode google user profile",
		},
		{
			name:            "userinfo missing identity fields",
			tokenStatus:     http.StatusOK,
			tokenBody:       `{"access_token":"token-123","token_type":"Bearer","expires_in":3600}`,
			userInfoStatus:  http.StatusOK,
			userInfoBody:    `{"name":"No Identity"}`,
			expectErr:       true,
			expectErrSubstr: "missing google user identity fields",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetGoogleOAuthConfigForTest()
			GoogleOAuthInit("test-client", "test-secret", "http://localhost:8080/callback")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.tokenStatus)
					_, _ = w.Write([]byte(tc.tokenBody))
				case "/oauth2/v2/userinfo":
					if authHeader := r.Header.Get("Authorization"); !strings.HasPrefix(authHeader, "Bearer ") {
						http.Error(w, "missing bearer token", http.StatusUnauthorized)
						return
					}
					w.WriteHeader(tc.userInfoStatus)
					_, _ = w.Write([]byte(tc.userInfoBody))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			setGoogleTokenEndpointForTest(server.URL + "/token")
			targetURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("failed to parse test server URL: %v", err)
			}

			httpClient := &http.Client{
				Transport: &rewriteUserInfoTransport{
					base:   server.Client().Transport,
					target: targetURL,
				},
			}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

			user, err := HandleGoogleCallback(ctx, "auth-code")
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.expectErrSubstr)
				}
				if tc.expectErrSubstr != "" && !strings.Contains(err.Error(), tc.expectErrSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.expectErrSubstr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
			if user == nil {
				t.Fatal("expected non-nil user")
			}
			if *user != *tc.expectUser {
				t.Fatalf("unexpected user: got %+v want %+v", *user, *tc.expectUser)
			}
		})
	}
}
