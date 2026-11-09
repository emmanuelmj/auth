package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	auth "github.com/GCET-Open-Source-Foundation/auth"
	"github.com/GCET-Open-Source-Foundation/auth/email"
)

type serverState struct {
	mu          sync.Mutex
	authInst    *auth.Auth
	mockStorage *MockStorage
	pgStorage   *auth.PostgresStorage
	rateLimiter *auth.RateLimiter
}

var state = &serverState{}

type jsonResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func sendJSON(w http.ResponseWriter, status int, data interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := jsonResponse{
		Success: err == nil,
		Data:    data,
	}
	if err != nil {
		resp.Error = err.Error()
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: auth-harness [server] [flags...]")
		os.Exit(1)
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 0, "port to listen on (0 for dynamic)")
	_ = fs.Parse(args)

	mux := http.NewServeMux()

	// Auth management
	mux.HandleFunc("/api/init", handleInit)
	mux.HandleFunc("/api/close", handleClose)
	mux.HandleFunc("/api/has-storage", handleHasStorage)
	mux.HandleFunc("/api/has-redis", handleHasRedis)
	mux.HandleFunc("/api/default-salt-params", handleDefaultSaltParams)
	mux.HandleFunc("/api/hash-password", handleHashPassword)

	// User lifecycle
	mux.HandleFunc("/api/register-user", handleRegisterUser)
	mux.HandleFunc("/api/login-user", handleLoginUser)
	mux.HandleFunc("/api/login-jwt", handleLoginJWT)
	mux.HandleFunc("/api/change-pass", handleChangePass)
	mux.HandleFunc("/api/delete-user", handleDeleteUser)
	mux.HandleFunc("/api/user-exists", handleUserExists)
	mux.HandleFunc("/api/list-users", handleListUsers)

	// JWT
	mux.HandleFunc("/api/generate-token", handleGenerateToken)
	mux.HandleFunc("/api/validate-token", handleValidateToken)

	// OTP
	mux.HandleFunc("/api/send-otp", handleSendOTP)
	mux.HandleFunc("/api/verify-otp", handleVerifyOTP)
	mux.HandleFunc("/api/otp-exists", handleOTPExists)
	mux.HandleFunc("/api/list-active-otps", handleListActiveOTPs)

	// Refresh Tokens
	mux.HandleFunc("/api/generate-refresh-token", handleGenerateRefreshToken)
	mux.HandleFunc("/api/validate-refresh-token", handleValidateRefreshToken)
	mux.HandleFunc("/api/rotate-refresh-token", handleRotateRefreshToken)
	mux.HandleFunc("/api/revoke-refresh-token", handleRevokeRefreshToken)
	mux.HandleFunc("/api/revoke-all-refresh-tokens", handleRevokeAllRefreshTokens)
	mux.HandleFunc("/api/cleanup-expired-refresh-tokens", handleCleanupExpiredRefreshTokens)

	// RBAC
	mux.HandleFunc("/api/create-role", handleCreateRole)
	mux.HandleFunc("/api/delete-role", handleDeleteRole)
	mux.HandleFunc("/api/create-space", handleCreateSpace)
	mux.HandleFunc("/api/delete-space", handleDeleteSpace)
	mux.HandleFunc("/api/create-permission", handleCreatePermission)
	mux.HandleFunc("/api/check-permission", handleCheckPermission)
	mux.HandleFunc("/api/delete-permission", handleDeletePermission)

	// Rate Limiter
	mux.HandleFunc("/api/ratelimit/create", handleRateLimitCreate)
	mux.HandleFunc("/api/ratelimit/allow", handleRateLimitAllow)
	mux.HandleFunc("/api/ratelimit/remaining", handleRateLimitRemaining)
	mux.HandleFunc("/api/ratelimit/reset", handleRateLimitReset)
	mux.HandleFunc("/api/ratelimit/stop", handleRateLimitStop)

	// OAuth & Email
	mux.HandleFunc("/api/google/login-url", handleGoogleLoginURL)
	mux.HandleFunc("/api/google/callback", handleGoogleCallback)
	mux.HandleFunc("/api/email/send", handleEmailSend)

	// Mock Storage control
	mux.HandleFunc("/api/mock/set-error", handleMockSetError)
	mux.HandleFunc("/api/mock/reset", handleMockReset)

	// Postgres Storage Direct Tests
	mux.HandleFunc("/api/postgres/check-tables", handlePostgresCheckTables)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start harness server: %v\n", err)
		os.Exit(1)
	}

	actualPort := ln.Addr().(*net.TCPAddr).Port
	fmt.Printf("READY: http://127.0.0.1:%d\n", actualPort)
	_ = os.Stdout.Sync()

	server := &http.Server{Handler: mux}
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
	}
}

func handleInit(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()

	var req struct {
		Storage       string  `json:"storage"` // "mock", "postgres", "none"
		DBPort        uint16  `json:"db_port"`
		DBUser        string  `json:"db_user"`
		DBPass        string  `json:"db_pass"`
		DBName        string  `json:"db_name"`
		DBHost        string  `json:"db_host"`
		Pepper        *string `json:"pepper"`
		JWTSecret     *string `json:"jwt_secret"`
		JWTExpiry     string  `json:"jwt_expiry"`
		OTPPepper     *string `json:"otp_pepper"`
		OTPLength     *int    `json:"otp_length"`
		OTPExpiry     string  `json:"otp_expiry"`
		RefreshExpiry *string `json:"refresh_expiry"`
		RefreshLength *int    `json:"refresh_length"`
		SMTPHost      *string `json:"smtp_host"`
		SMTPPort      *string `json:"smtp_port"`
		SMTPUser      *string `json:"smtp_user"`
		SMTPPass      *string `json:"smtp_pass"`
		OAuthClientID *string `json:"oauth_client_id"`
		OAuthSecret   *string `json:"oauth_client_secret"`
		OAuthRedirect *string `json:"oauth_redirect"`
		Policy        *struct {
			MinLength        int  `json:"min_length"`
			MaxLength        int  `json:"max_length"`
			RequireUppercase bool `json:"require_uppercase"`
			RequireNumber    bool `json:"require_number"`
			RequireSpecial   bool `json:"require_special"`
		} `json:"password_policy"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}

	if state.authInst != nil {
		state.authInst.Close()
		state.authInst = nil
	}

	var opts []auth.Option

	if req.Storage == "mock" {
		if state.mockStorage == nil {
			state.mockStorage = NewMockStorage()
		}
		opts = append(opts, auth.WithStorage(state.mockStorage))
	} else if req.Storage == "postgres" {
		pg, err := auth.NewPostgresStorage(context.Background(), req.DBPort, req.DBUser, req.DBPass, req.DBName, req.DBHost)
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, nil, err)
			return
		}
		state.pgStorage = pg
		opts = append(opts, auth.WithStorage(pg))
	}

	if req.Pepper != nil {
		opts = append(opts, auth.WithPepper([]byte(*req.Pepper)))
	}

	if req.JWTSecret != nil {
		opts = append(opts, auth.WithJWT([]byte(*req.JWTSecret), parseDuration(req.JWTExpiry)))
	}

	if req.OTPPepper != nil || req.OTPLength != nil || req.OTPExpiry != "" {
		pep := []byte{}
		if req.OTPPepper != nil {
			pep = []byte(*req.OTPPepper)
		}
		length := 0
		if req.OTPLength != nil {
			length = *req.OTPLength
		}
		opts = append(opts, auth.WithOTP(length, pep, parseDuration(req.OTPExpiry)))
	}

	if req.RefreshExpiry != nil || req.RefreshLength != nil {
		dur := time.Duration(0)
		if req.RefreshExpiry != nil {
			dur = parseDuration(*req.RefreshExpiry)
		}
		length := 0
		if req.RefreshLength != nil {
			length = *req.RefreshLength
		}
		opts = append(opts, auth.WithRefreshToken(dur, length))
	}

	if req.SMTPHost != nil || req.SMTPPort != nil || req.SMTPUser != nil || req.SMTPPass != nil {
		host, port, user, pass := "", "", "", ""
		if req.SMTPHost != nil {
			host = *req.SMTPHost
		}
		if req.SMTPPort != nil {
			port = *req.SMTPPort
		}
		if req.SMTPUser != nil {
			user = *req.SMTPUser
		}
		if req.SMTPPass != nil {
			pass = *req.SMTPPass
		}
		opts = append(opts, auth.WithSMTP(user, pass, host, port))
	}

	if req.OAuthClientID != nil || req.OAuthSecret != nil || req.OAuthRedirect != nil {
		cid, sec, red := "", "", ""
		if req.OAuthClientID != nil {
			cid = *req.OAuthClientID
		}
		if req.OAuthSecret != nil {
			sec = *req.OAuthSecret
		}
		if req.OAuthRedirect != nil {
			red = *req.OAuthRedirect
		}
		opts = append(opts, auth.WithOAuth(cid, sec, red))
	}

	if req.Policy != nil {
		opts = append(opts, auth.WithPasswordPolicy(auth.PasswordPolicy{
			MinLength:        req.Policy.MinLength,
			MaxLength:        req.Policy.MaxLength,
			RequireUppercase: req.Policy.RequireUppercase,
			RequireNumber:    req.Policy.RequireNumber,
			RequireSpecial:   req.Policy.RequireSpecial,
		}))
	}

	a, err := auth.New(context.Background(), opts...)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	state.authInst = a

	sendJSON(w, http.StatusOK, map[string]string{"status": "initialized"}, nil)
}

func handleClose(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst != nil {
		state.authInst.Close()
		state.authInst = nil
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "closed"}, nil)
}

func handleHasStorage(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusOK, map[string]bool{"has_storage": false}, nil)
		return
	}
	sendJSON(w, http.StatusOK, map[string]bool{"has_storage": state.authInst.HasStorage()}, nil)
}

func handleHasRedis(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusOK, map[string]bool{"has_redis": false}, nil)
		return
	}
	sendJSON(w, http.StatusOK, map[string]bool{"has_redis": state.authInst.HasRedis()}, nil)
}

func handleDefaultSaltParams(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory"`
		Threads uint8  `json:"threads"`
		KeyLen  uint32 `json:"key_len"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.DefaultSaltParameters(req.Time, req.Memory, req.Threads, req.KeyLen)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "updated"}, nil)
}

func handleHashPassword(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Password string `json:"password"`
		Salt     string `json:"salt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	hash, err := state.authInst.HashPassword(req.Password, req.Salt)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"hash": hash}, nil)
}

func handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.RegisterUser(r.Context(), req.Username, req.Password)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "registered"}, nil)
}

func handleLoginUser(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.LoginUser(r.Context(), req.Username, req.Password)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "logged_in"}, nil)
}

func handleLoginJWT(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	claims, err := state.authInst.LoginJWT(r.Context(), req.Token)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, claims, nil)
}

func handleChangePass(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.ChangePass(r.Context(), req.Username, req.NewPassword)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "password_changed"}, nil)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.DeleteUser(r.Context(), req.Username)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, nil)
}

func handleUserExists(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	exists, err := state.authInst.UserExists(r.Context(), req.Email)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]bool{"exists": exists}, nil)
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	users, err := state.authInst.ListUsers(r.Context(), limit, offset)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, users, nil)
}

func handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username string `json:"username"`
		Expiry   string `json:"expiry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	var token string
	var err error
	if req.Expiry != "" {
		token, err = state.authInst.GenerateToken(r.Context(), req.Username, parseDuration(req.Expiry))
	} else {
		token, err = state.authInst.GenerateToken(r.Context(), req.Username)
	}
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"token": token}, nil)
}

func handleValidateToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	claims, err := state.authInst.ValidateToken(r.Context(), req.Token)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, claims, nil)
}

func handleSendOTP(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.SendOTP(r.Context(), req.Email)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "sent"}, nil)
}

func handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.VerifyOTP(r.Context(), req.Email, req.Code)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "verified"}, nil)
}

func handleOTPExists(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	exists, err := state.authInst.OTPExists(r.Context(), req.Email)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]bool{"exists": exists}, nil)
}

func handleListActiveOTPs(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	emails, err := state.authInst.ListActiveOTPs(r.Context(), limit, offset)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, emails, nil)
}

func handleGenerateRefreshToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	token, err := state.authInst.GenerateRefreshToken(r.Context(), req.UserID)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"token": token}, nil)
}

func handleValidateRefreshToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	userID, err := state.authInst.ValidateRefreshToken(r.Context(), req.Token)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"user_id": userID}, nil)
}

func handleRotateRefreshToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		OldToken string `json:"old_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	newToken, userID, err := state.authInst.RotateRefreshToken(r.Context(), req.OldToken)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"new_token": newToken, "user_id": userID}, nil)
}

func handleRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.RevokeRefreshToken(r.Context(), req.Token)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "revoked"}, nil)
}

func handleRevokeAllRefreshTokens(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.RevokeAllUserRefreshTokens(r.Context(), req.UserID)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "all_revoked"}, nil)
}

func handleCleanupExpiredRefreshTokens(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	err := state.authInst.CleanupExpiredRefreshTokens(r.Context())
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "cleaned"}, nil)
}

func handleCreateRole(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.CreateRole(r.Context(), req.Name)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "created"}, nil)
}

func handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.DeleteRole(r.Context(), req.Name)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, nil)
}

func handleCreateSpace(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Name      string `json:"name"`
		Authority int    `json:"authority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.CreateSpace(r.Context(), req.Name, req.Authority)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "created"}, nil)
}

func handleDeleteSpace(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.DeleteSpace(r.Context(), req.Name)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, nil)
}

func handleCreatePermission(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username  string `json:"username"`
		SpaceName string `json:"space_name"`
		Role      string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.CreatePermissions(r.Context(), req.Username, req.SpaceName, req.Role)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "created"}, nil)
}

func handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username  string `json:"username"`
		SpaceName string `json:"space_name"`
		Role      string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.CheckPermissions(r.Context(), req.Username, req.SpaceName, req.Role)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "authorized"}, nil)
}

func handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Username  string `json:"username"`
		SpaceName string `json:"space_name"`
		Role      string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.authInst.DeletePermission(r.Context(), req.Username, req.SpaceName, req.Role)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "deleted"}, nil)
}

func handleRateLimitCreate(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var req struct {
		MaxRequests int    `json:"max_requests"`
		Window      string `json:"window"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	rl, err := auth.NewRateLimiter(auth.RateLimiterConfig{
		MaxRequests: req.MaxRequests,
		Window:      parseDuration(req.Window),
	})
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	state.rateLimiter = rl
	sendJSON(w, http.StatusOK, map[string]string{"status": "created"}, nil)
}

func handleRateLimitAllow(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.rateLimiter == nil {
		sendJSON(w, http.StatusBadRequest, nil, errors.New("rate limiter not initialized"))
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.rateLimiter.Allow(r.Context(), req.Key)
	if err != nil {
		sendJSON(w, http.StatusTooManyRequests, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "allowed"}, nil)
}

func handleRateLimitRemaining(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.rateLimiter == nil {
		sendJSON(w, http.StatusBadRequest, nil, errors.New("rate limiter not initialized"))
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	rem, err := state.rateLimiter.Remaining(r.Context(), req.Key)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]int{"remaining": rem}, nil)
}

func handleRateLimitReset(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.rateLimiter == nil {
		sendJSON(w, http.StatusBadRequest, nil, errors.New("rate limiter not initialized"))
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := state.rateLimiter.Reset(r.Context(), req.Key)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "reset"}, nil)
}

func handleRateLimitStop(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.rateLimiter != nil {
		state.rateLimiter.Stop()
		state.rateLimiter = nil
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "stopped"}, nil)
}

func handleGoogleLoginURL(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	url, err := state.authInst.GetGoogleLoginURL(r.Context(), req.State)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"url": url}, nil)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.authInst == nil {
		sendJSON(w, http.StatusBadRequest, nil, auth.ErrNotInitialized)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	token, err := state.authInst.HandleGoogleCallback(r.Context(), req.Code)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"token": token}, nil)
}

func handleEmailSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host      string `json:"host"`
		Port      string `json:"port"`
		FromEmail string `json:"from_email"`
		Password  string `json:"password"`
		ToEmail   string `json:"to_email"`
		Subject   string `json:"subject"`
		Body      string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	err := email.Send(req.Host, req.Port, req.FromEmail, req.Password, req.ToEmail, req.Subject, req.Body)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "sent"}, nil)
}

func handleMockSetError(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mockStorage == nil {
		sendJSON(w, http.StatusBadRequest, nil, errors.New("mock storage not active"))
		return
	}
	var req struct {
		Hook string `json:"hook"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}

	var injectErr error
	if req.Msg != "" {
		injectErr = errors.New(req.Msg)
	}

	switch req.Hook {
	case "check_tables":
		state.mockStorage.CheckTablesErr = injectErr
	case "insert_user":
		state.mockStorage.InsertUserErr = injectErr
	case "update_password":
		state.mockStorage.UpdateUserPasswordErr = injectErr
	case "delete_user":
		state.mockStorage.DeleteUserErr = injectErr
	case "user_exists":
		state.mockStorage.UserExistsErr = injectErr
	case "get_user":
		state.mockStorage.GetUserErr = injectErr
	case "list_users":
		state.mockStorage.ListUsersErr = injectErr
	case "upsert_oauth":
		state.mockStorage.UpsertOAuthUserErr = injectErr
	case "insert_space":
		state.mockStorage.InsertSpaceErr = injectErr
	case "delete_space":
		state.mockStorage.DeleteSpaceErr = injectErr
	case "insert_role":
		state.mockStorage.InsertRoleErr = injectErr
	case "delete_role":
		state.mockStorage.DeleteRoleErr = injectErr
	case "insert_permission":
		state.mockStorage.InsertPermissionErr = injectErr
	case "check_permission":
		state.mockStorage.CheckPermissionErr = injectErr
	case "delete_permission":
		state.mockStorage.DeletePermissionErr = injectErr
	case "insert_otp":
		state.mockStorage.InsertOTPErr = injectErr
	case "get_otp":
		state.mockStorage.GetOTPErr = injectErr
	case "delete_otp":
		state.mockStorage.DeleteOTPErr = injectErr
	case "list_active_otps":
		state.mockStorage.ListActiveOTPsErr = injectErr
	case "cleanup_otps":
		state.mockStorage.CleanupOTPErr = injectErr
	case "insert_refresh":
		state.mockStorage.InsertRefreshErr = injectErr
	case "get_refresh":
		state.mockStorage.GetRefreshErr = injectErr
	case "revoke_refresh":
		state.mockStorage.RevokeRefreshErr = injectErr
	case "revoke_all_refresh":
		state.mockStorage.RevokeAllRefreshErr = injectErr
	case "cleanup_refresh":
		state.mockStorage.CleanupRefreshErr = injectErr
	default:
		sendJSON(w, http.StatusBadRequest, nil, fmt.Errorf("unknown hook: %s", req.Hook))
		return
	}

	sendJSON(w, http.StatusOK, map[string]string{"status": "hook_set"}, nil)
}

func handleMockReset(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mockStorage != nil {
		state.mockStorage.Reset()
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "reset"}, nil)
}

func handlePostgresCheckTables(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var req struct {
		Port uint16 `json:"port"`
		User string `json:"user"`
		Pass string `json:"pass"`
		Name string `json:"name"`
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	pg, err := auth.NewPostgresStorage(r.Context(), req.Port, req.User, req.Pass, req.Name, req.Host)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	defer pg.Close()
	err = pg.CheckTables(r.Context())
	if err != nil {
		sendJSON(w, http.StatusBadRequest, nil, err)
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"}, nil)
}
