package handler

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/slederer/open-source-streaming-service/backend/internal/model"
)

// ListVideos handles GET /api/videos
func (h *Handler) ListVideos(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	page := queryInt(r, "page", 1)
	limit := queryInt(r, "limit", 20)
	if limit > 100 {
		limit = 100
	}

	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "failed to list videos")
		return
	}

	videos, total, err := h.Store.ListVideos(r.Context(), category, page, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list videos")
		return
	}

	if videos == nil {
		videos = []model.Video{}
	}

	writeJSON(w, http.StatusOK, model.PaginatedResponse{
		Data:       videos,
		Page:       page,
		Limit:      limit,
		TotalCount: total,
	})
}

// GetVideo handles GET /api/videos/{id}
func (h *Handler) GetVideo(w http.ResponseWriter, r *http.Request) {
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

	cats, _ := h.Store.GetCategoriesForVideo(r.Context(), id)
	if cats == nil {
		cats = []model.Category{}
	}

	writeJSON(w, http.StatusOK, model.VideoWithCategories{
		Video:      *video,
		Categories: cats,
	})
}
