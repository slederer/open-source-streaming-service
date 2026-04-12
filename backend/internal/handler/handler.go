package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/store"
)

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	Store  *store.Store
	Config *config.Config
}

// New creates a new Handler.
func New(s *store.Store, cfg *config.Config) *Handler {
	return &Handler{Store: s, Config: cfg}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return defaultVal
	}
	return n
}
