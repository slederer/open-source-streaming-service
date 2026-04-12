package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/handler"
)

func TestGoogleLogin_NotConfigured(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{} // No Google OAuth config
	h := handler.New(nil, cfg)
	r.Get("/api/auth/google", h.GoogleLogin)

	req := httptest.NewRequest("GET", "/api/auth/google", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when OAuth not configured, got %d", w.Code)
	}
}

func TestGoogleLogin_Configured(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-secret",
		APIBase:            "http://localhost:8080",
	}
	h := handler.New(nil, cfg)
	r.Get("/api/auth/google", h.GoogleLogin)

	req := httptest.NewRequest("GET", "/api/auth/google", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should redirect to Google
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc == "" {
		t.Error("expected Location header")
	}
}

func TestGetMe_NoSession(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{}
	h := handler.New(nil, cfg)
	r.Get("/api/auth/me", h.GetMe)

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["user"] != nil {
		t.Error("expected user to be nil when no session")
	}
}

func TestLogout_NoCookie(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{}
	h := handler.New(nil, cfg)
	r.Post("/api/auth/logout", h.Logout)

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
