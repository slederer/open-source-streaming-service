package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/handler"
)

func TestMockVAST_ReturnsValidXML(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{
		CloudFrontDomain: "test.cloudfront.net",
		APIBase:          "http://localhost:8080",
	}
	h := handler.New(nil, cfg)
	r.Get("/api/ads/vast", h.MockVAST)

	req := httptest.NewRequest("GET", "/api/ads/vast", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/xml" {
		t.Errorf("expected content-type application/xml, got %s", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<VAST version=\"3.0\">") {
		t.Error("response does not contain VAST 3.0 root element")
	}
	if !strings.Contains(body, "test.cloudfront.net") {
		t.Error("response does not contain CloudFront domain")
	}
	if !strings.Contains(body, "<Duration>00:00:15</Duration>") {
		t.Error("response does not contain 15s duration")
	}
}

func TestAdImpression_Returns204(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{}
	h := handler.New(nil, cfg)
	r.Get("/api/ads/impression", h.AdImpression)

	req := httptest.NewRequest("GET", "/api/ads/impression?ad=test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}
