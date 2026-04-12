package handler

import (
	"net/http"

	"github.com/slederer/open-source-streaming-service/backend/internal/model"
)

// ListCategories handles GET /api/categories
func (h *Handler) ListCategories(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to list categories")
		return
	}

	cats, err := h.Store.ListCategories(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list categories")
		return
	}
	if cats == nil {
		cats = []model.Category{}
	}
	writeJSON(w, http.StatusOK, cats)
}
