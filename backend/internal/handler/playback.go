package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
)

// GetVideoPlayback handles GET /api/videos/{id}/playback
// Returns MediaTailor session URL + DRM token for the given video.
func (h *Handler) GetVideoPlayback(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing video id")
		return
	}

	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to get video")
		return
	}

	video, err := h.Store.GetVideo(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "video not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get video")
		return
	}

	if video.Status != "ready" {
		writeError(w, http.StatusConflict, "video not yet ready for playback")
		return
	}

	resp := map[string]string{
		"manifest_hls":  video.ManifestHLS,
		"manifest_dash": video.ManifestDASH,
	}

	// Add MediaTailor session URL if configured
	if h.Config.MediaTailorVODEndpoint != "" {
		resp["session_url_hls"] = fmt.Sprintf("%s/v1/session/%s/manifest.m3u8",
			h.Config.MediaTailorVODEndpoint, video.EncodingJobID)
		resp["session_url_dash"] = fmt.Sprintf("%s/v1/session/%s/manifest.mpd",
			h.Config.MediaTailorVODEndpoint, video.EncodingJobID)
	}

	// Add DRM token if DoveRunner (formerly PallyCon) is configured
	if h.Config.PallyConSiteID != "" && video.DRMContentID != "" {
		resp["drm_token"] = generatePallyConToken(h.Config, video.DRMContentID)
		resp["drm_widevine_url"] = "https://license.pallycon.com/ri/widevineLicense"
		resp["drm_fairplay_url"] = "https://license.pallycon.com/ri/fpLicense"
		resp["drm_fairplay_cert_url"] = fmt.Sprintf(
			"https://license.pallycon.com/ri/fpsKeyManager.do?siteId=%s", h.Config.PallyConSiteID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetLivePlayback handles GET /api/live/channels/{id}/playback
func (h *Handler) GetLivePlayback(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel id")
		return
	}

	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to get channel")
		return
	}

	ch, err := h.Store.GetLiveChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get channel")
		return
	}

	resp := map[string]string{
		"manifest_hls":  ch.ManifestHLS,
		"manifest_dash": ch.ManifestDASH,
	}

	if h.Config.MediaTailorLiveEndpoint != "" && ch.EncodingID != "" {
		resp["session_url_hls"] = fmt.Sprintf("%s/v1/session/%s/manifest.m3u8",
			h.Config.MediaTailorLiveEndpoint, ch.EncodingID)
		resp["session_url_dash"] = fmt.Sprintf("%s/v1/session/%s/manifest.mpd",
			h.Config.MediaTailorLiveEndpoint, ch.EncodingID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// generatePallyConToken creates a DoveRunner (formerly PallyCon) custom data token.
// In production this would be a proper JWT signed with the site key.
func generatePallyConToken(cfg *config.Config, contentID string) string {
	// Placeholder: real implementation signs a JWT with PallyConSiteKey
	return fmt.Sprintf("%s:%s:%s", cfg.PallyConSiteID, cfg.PallyConSiteKey, contentID)
}
