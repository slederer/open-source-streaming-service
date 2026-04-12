package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const sessionCookieName = "oss_session"
const sessionDuration = 30 * 24 * time.Hour // 30 days

type googleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func (h *Handler) googleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.Config.GoogleClientID,
		ClientSecret: h.Config.GoogleClientSecret,
		RedirectURL:  h.Config.APIBase + "/api/auth/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
}

// GoogleLogin redirects to Google OAuth consent screen.
// GET /api/auth/google
func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	if h.Config.GoogleClientID == "" {
		writeError(w, http.StatusServiceUnavailable, "Google OAuth not configured")
		return
	}

	state, _ := generateState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.googleOAuthConfig().AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleCallback handles the OAuth callback from Google.
// GET /api/auth/google/callback
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		writeError(w, http.StatusBadRequest, "invalid oauth state")
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing authorization code")
		return
	}

	oauthConfig := h.googleOAuthConfig()
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("OAuth exchange error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to exchange token")
		return
	}

	// Fetch user info from Google
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get user info")
		return
	}
	defer resp.Body.Close()

	var userInfo googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to parse user info")
		return
	}

	// Upsert user in database
	user, err := h.Store.UpsertUser(r.Context(), userInfo.ID, userInfo.Email, userInfo.Name, userInfo.Picture)
	if err != nil {
		log.Printf("UpsertUser error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Create session
	sessionToken, err := h.Store.CreateSession(r.Context(), user.ID, sessionDuration)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Redirect to frontend
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Logout clears the session.
// POST /api/auth/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		h.Store.DeleteSession(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// GetMe returns the current authenticated user.
// GET /api/auth/me
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"user": nil})
		return
	}

	if h.Store == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"user": nil})
		return
	}

	user, err := h.Store.GetSessionUser(r.Context(), cookie.Value)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"user": nil})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"user": user})
}

func generateState() (string, error) {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b), nil
}
