package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

// BitmovinWebhookPayload represents the webhook body from Bitmovin encoding.
type BitmovinWebhookPayload struct {
	EncodingID string `json:"encodingId"`
	Status     string `json:"status"`
}

// BitmovinWebhook handles POST /api/webhooks/bitmovin
func (h *Handler) BitmovinWebhook(w http.ResponseWriter, r *http.Request) {
	var payload BitmovinWebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if payload.EncodingID == "" {
		writeError(w, http.StatusBadRequest, "missing encodingId")
		return
	}

	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to look up video")
		return
	}

	video, err := h.Store.GetVideoByEncodingJobID(r.Context(), payload.EncodingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no video found for encoding")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to look up video")
		return
	}

	if payload.Status == "FINISHED" {
		hlsURL := fmt.Sprintf("https://%s/%s/manifest.m3u8", h.Config.CloudFrontDomain, payload.EncodingID)
		dashURL := fmt.Sprintf("https://%s/%s/manifest.mpd", h.Config.CloudFrontDomain, payload.EncodingID)

		if err := h.Store.UpdateVideoManifests(r.Context(), video.ID, hlsURL, dashURL); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update video")
			return
		}
		log.Printf("Video %s encoding complete: %s", video.ID, video.Title)
	} else if payload.Status == "ERROR" {
		if err := h.Store.UpdateVideoStatus(r.Context(), video.ID, "error"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update video status")
			return
		}
		log.Printf("Video %s encoding failed: %s", video.ID, video.Title)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
