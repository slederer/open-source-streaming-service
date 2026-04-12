package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/handler"
)

func TestBitmovinWebhook_InvalidPayload(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)
	r.Post("/api/webhooks/bitmovin", h.BitmovinWebhook)

	req := httptest.NewRequest("POST", "/api/webhooks/bitmovin", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid payload, got %d", w.Code)
	}
}

func TestBitmovinWebhook_MissingEncodingID(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)
	r.Post("/api/webhooks/bitmovin", h.BitmovinWebhook)

	payload := handler.BitmovinWebhookPayload{Status: "FINISHED"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/webhooks/bitmovin", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing encodingId, got %d", w.Code)
	}
}

func TestBitmovinWebhook_EncodingNotFound(t *testing.T) {
	// Without a DB/store, the lookup will fail
	r := chi.NewRouter()
	cfg := &config.Config{CloudFrontDomain: "test.cloudfront.net"}
	h := handler.New(nil, cfg)
	r.Post("/api/webhooks/bitmovin", h.BitmovinWebhook)

	payload := handler.BitmovinWebhookPayload{
		EncodingID: "nonexistent-encoding",
		Status:     "FINISHED",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/webhooks/bitmovin", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Without store, expect 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
