package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/handler"
	"github.com/slederer/open-source-streaming-service/backend/internal/store"
)

func main() {
	_ = godotenv.Load()

	cfg := config.Load()

	db, err := store.Connect(cfg.DBUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	s := store.New(db)
	h := handler.New(s, cfg)

	r := NewRouter(h)

	log.Printf("Starting server on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// NewRouter creates the chi router with all routes. Exported for testing.
func NewRouter(h *handler.Handler) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/api", func(r chi.Router) {
		// Auth endpoints
		r.Get("/auth/google", h.GoogleLogin)
		r.Get("/auth/google/callback", h.GoogleCallback)
		r.Post("/auth/logout", h.Logout)
		r.Get("/auth/me", h.GetMe)

		// Public endpoints
		r.Get("/videos", h.ListVideos)
		r.Get("/videos/{id}", h.GetVideo)
		r.Get("/videos/{id}/playback", h.GetVideoPlayback)
		r.Get("/categories", h.ListCategories)
		r.Get("/live/channels", h.ListLiveChannels)
		r.Get("/live/channels/{id}/playback", h.GetLivePlayback)

		// Ad endpoints
		r.Get("/ads/vast", h.MockVAST)
		r.Get("/ads/impression", h.AdImpression)

		// Webhook endpoints
		r.Post("/webhooks/bitmovin", h.BitmovinWebhook)
	})

	return r
}
