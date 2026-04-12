package handler

import (
	"net/http"

	"github.com/slederer/open-source-streaming-service/backend/internal/model"
)

// ListLiveChannels handles GET /api/live/channels
func (h *Handler) ListLiveChannels(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to list live channels")
		return
	}

	channels, err := h.Store.ListLiveChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list live channels")
		return
	}
	if channels == nil {
		channels = []model.LiveChannel{}
	}
	writeJSON(w, http.StatusOK, channels)
}
