package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/handler"
)

func TestGetVideoPlayback_MissingID(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)

	// Route without {id} param to test missing ID
	r.Get("/api/videos/playback", h.GetVideoPlayback)

	req := httptest.NewRequest("GET", "/api/videos/playback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing id, got %d", w.Code)
	}
}

func TestGetVideoPlayback_VideoNotFound(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)
	r.Get("/api/videos/{id}/playback", h.GetVideoPlayback)

	req := httptest.NewRequest("GET", "/api/videos/nonexistent/playback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Without store, expect 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestGetLivePlayback_InvalidID(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)
	r.Get("/api/live/channels/{id}/playback", h.GetLivePlayback)

	req := httptest.NewRequest("GET", "/api/live/channels/abc/playback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid id, got %d", w.Code)
	}
}
