package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/slederer/open-source-streaming-service/backend/internal/config"
	"github.com/slederer/open-source-streaming-service/backend/internal/model"
	"github.com/slederer/open-source-streaming-service/backend/internal/store"
)

// CatalogEntry represents a single video in catalog.json.
type CatalogEntry struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	SourceURL   string   `json:"source_url"`
	Duration    int      `json:"duration"`
	Year        int      `json:"year"`
	License     string   `json:"license"`
	Attribution string   `json:"attribution"`
	Categories  []string `json:"categories"`
}

func main() {
	catalogPath := flag.String("catalog", "content/catalog.json", "Path to catalog.json")
	dryRun := flag.Bool("dry-run", false, "Print what would be done without making changes")
	flag.Parse()

	_ = godotenv.Load()
	cfg := config.Load()

	entries, err := loadCatalog(*catalogPath)
	if err != nil {
		log.Fatalf("Failed to load catalog: %v", err)
	}

	log.Printf("Loaded %d entries from catalog", len(entries))

	if *dryRun {
		for i, e := range entries {
			log.Printf("[DRY RUN] %d. %s (%d) — %s", i+1, e.Title, e.Year, e.SourceURL)
		}
		return
	}

	db, err := store.Connect(cfg.DBUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	s := store.New(db)
	ctx := context.Background()

	for i, entry := range entries {
		log.Printf("[%d/%d] Processing: %s", i+1, len(entries), entry.Title)

		if err := ingestVideo(ctx, s, cfg, entry); err != nil {
			log.Printf("  ERROR: %v", err)
			continue
		}

		log.Printf("  OK: inserted into database")
	}

	log.Println("Ingestion complete.")
}

func loadCatalog(path string) ([]CatalogEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading catalog file: %w", err)
	}

	var entries []CatalogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing catalog JSON: %w", err)
	}

	return entries, nil
}

func ingestVideo(ctx context.Context, s *store.Store, cfg *config.Config, entry CatalogEntry) error {
	slug := slugify(entry.Title)
	drmContentID := fmt.Sprintf("oss-%s", slug)

	video := &model.Video{
		Title:        entry.Title,
		Description:  entry.Description,
		Duration:     entry.Duration,
		Year:         entry.Year,
		License:      entry.License,
		Attribution:  entry.Attribution,
		SourceURL:    entry.SourceURL,
		DRMContentID: drmContentID,
		Status:       model.StatusPending,
	}

	if err := s.CreateVideo(ctx, video); err != nil {
		return fmt.Errorf("creating video record: %w", err)
	}

	// Assign categories
	for _, catSlug := range entry.Categories {
		cat, err := s.GetCategoryBySlug(ctx, catSlug)
		if err != nil {
			log.Printf("  WARNING: category '%s' not found, skipping", catSlug)
			continue
		}
		if err := s.AddVideoCategory(ctx, video.ID, cat.ID); err != nil {
			log.Printf("  WARNING: failed to add category '%s': %v", catSlug, err)
		}
	}

	// In a full implementation, the next steps would be:
	// 1. Download master: http.Get(entry.SourceURL) → stream to S3
	// 2. Call PallyCon KMS API to get DRM keys for this content ID
	// 3. Create Bitmovin VOD Encoding with:
	//    - S3 Input (master file)
	//    - S3 Output (encoded segments)
	//    - H264 codec configs (240p, 480p, 720p, 1080p) + AAC
	//    - CENC DRM muxings (Widevine) + FairPlay DRM muxings
	//    - SCTE-35 markers at AI-detected scene boundaries
	//    - HLS + DASH manifests
	//    - Per-Title encoding mode
	// 4. Register webhook: POST /api/webhooks/bitmovin
	// 5. Start encoding
	// 6. Trigger AI Content Analytics for scene descriptions + thumbnails
	//
	// These require valid Bitmovin API key + AWS credentials.
	// For now, we insert the DB record so the catalog is browsable.
	// The encoding pipeline is triggered separately or via POST /api/admin/ingest.

	log.Printf("  Created video ID=%s, DRM content ID=%s", video.ID, drmContentID)
	log.Printf("  TODO: S3 upload → Bitmovin encoding → webhook → status=ready")

	return nil
}

func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r == ' ' || r == '-' || r == '_' {
			return '-'
		}
		return -1
	}, s)
	// Collapse multiple hyphens
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}
