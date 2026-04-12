package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/slederer/open-source-streaming-service/backend/internal/model"
)

// Store provides database access methods.
type Store struct {
	db *sqlx.DB
}

// New creates a new Store with the given database connection.
func New(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// Connect opens a connection to the Postgres database.
func Connect(databaseURL string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	return db, nil
}

// --- Videos ---

func (s *Store) ListVideos(ctx context.Context, categorySlug string, page, limit int) ([]model.Video, int, error) {
	offset := (page - 1) * limit

	var countQuery, listQuery string
	var args []interface{}

	if categorySlug != "" {
		countQuery = `
			SELECT COUNT(DISTINCT v.id)
			FROM videos v
			JOIN video_categories vc ON v.id = vc.video_id
			JOIN categories c ON vc.category_id = c.id
			WHERE v.status = 'ready' AND c.slug = $1`
		listQuery = `
			SELECT DISTINCT v.*
			FROM videos v
			JOIN video_categories vc ON v.id = vc.video_id
			JOIN categories c ON vc.category_id = c.id
			WHERE v.status = 'ready' AND c.slug = $1
			ORDER BY v.created_at DESC
			LIMIT $2 OFFSET $3`
		args = []interface{}{categorySlug, limit, offset}
	} else {
		countQuery = `SELECT COUNT(*) FROM videos WHERE status = 'ready'`
		listQuery = `
			SELECT * FROM videos
			WHERE status = 'ready'
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2`
		args = []interface{}{limit, offset}
	}

	var total int
	if categorySlug != "" {
		err := s.db.GetContext(ctx, &total, countQuery, categorySlug)
		if err != nil {
			return nil, 0, fmt.Errorf("counting videos: %w", err)
		}
	} else {
		err := s.db.GetContext(ctx, &total, countQuery)
		if err != nil {
			return nil, 0, fmt.Errorf("counting videos: %w", err)
		}
	}

	var videos []model.Video
	err := s.db.SelectContext(ctx, &videos, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing videos: %w", err)
	}

	return videos, total, nil
}

func (s *Store) GetVideo(ctx context.Context, id string) (*model.Video, error) {
	var v model.Video
	err := s.db.GetContext(ctx, &v, `SELECT * FROM videos WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("getting video %s: %w", id, err)
	}
	return &v, nil
}

func (s *Store) GetVideoByEncodingJobID(ctx context.Context, encodingJobID string) (*model.Video, error) {
	var v model.Video
	err := s.db.GetContext(ctx, &v, `SELECT * FROM videos WHERE encoding_job_id = $1`, encodingJobID)
	if err != nil {
		return nil, fmt.Errorf("getting video by encoding job %s: %w", encodingJobID, err)
	}
	return &v, nil
}

func (s *Store) CreateVideo(ctx context.Context, v *model.Video) error {
	if v.ThumbnailURLs == nil {
		v.ThumbnailURLs = json.RawMessage(`[]`)
	}
	if v.AdBreaks == nil {
		v.AdBreaks = json.RawMessage(`[]`)
	}
	query := `
		INSERT INTO videos (title, description, ai_description, duration, year, license, attribution,
			source_url, poster_url, thumbnail_urls, manifest_hls, manifest_dash, encoding_job_id,
			drm_content_id, ad_breaks, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at`
	return s.db.QueryRowContext(ctx, query,
		v.Title, v.Description, v.AIDescription, v.Duration, v.Year, v.License, v.Attribution,
		v.SourceURL, v.PosterURL, v.ThumbnailURLs, v.ManifestHLS, v.ManifestDASH, v.EncodingJobID,
		v.DRMContentID, v.AdBreaks, v.Status,
	).Scan(&v.ID, &v.CreatedAt)
}

func (s *Store) UpdateVideoStatus(ctx context.Context, id string, status model.VideoStatus) error {
	_, err := s.db.ExecContext(ctx, `UPDATE videos SET status = $1 WHERE id = $2`, status, id)
	return err
}

func (s *Store) UpdateVideoManifests(ctx context.Context, id, hlsURL, dashURL string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE videos SET manifest_hls = $1, manifest_dash = $2, status = 'ready' WHERE id = $3`,
		hlsURL, dashURL, id)
	return err
}

func (s *Store) UpdateVideoAIMetadata(ctx context.Context, id, aiDesc string, thumbnails json.RawMessage) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE videos SET ai_description = $1, thumbnail_urls = $2 WHERE id = $3`,
		aiDesc, thumbnails, id)
	return err
}

// --- Categories ---

func (s *Store) ListCategories(ctx context.Context) ([]model.Category, error) {
	var cats []model.Category
	err := s.db.SelectContext(ctx, &cats, `SELECT * FROM categories ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing categories: %w", err)
	}
	return cats, nil
}

func (s *Store) GetCategoriesForVideo(ctx context.Context, videoID string) ([]model.Category, error) {
	var cats []model.Category
	err := s.db.SelectContext(ctx, &cats, `
		SELECT c.* FROM categories c
		JOIN video_categories vc ON c.id = vc.category_id
		WHERE vc.video_id = $1
		ORDER BY c.name`, videoID)
	if err != nil {
		return nil, fmt.Errorf("getting categories for video %s: %w", videoID, err)
	}
	return cats, nil
}

func (s *Store) AddVideoCategory(ctx context.Context, videoID string, categoryID int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO video_categories (video_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		videoID, categoryID)
	return err
}

func (s *Store) GetCategoryBySlug(ctx context.Context, slug string) (*model.Category, error) {
	var c model.Category
	err := s.db.GetContext(ctx, &c, `SELECT * FROM categories WHERE slug = $1`, slug)
	if err != nil {
		return nil, fmt.Errorf("getting category by slug %s: %w", slug, err)
	}
	return &c, nil
}

// --- Live Channels ---

func (s *Store) ListLiveChannels(ctx context.Context) ([]model.LiveChannel, error) {
	var channels []model.LiveChannel
	err := s.db.SelectContext(ctx, &channels,
		`SELECT * FROM live_channels WHERE is_active = true ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing live channels: %w", err)
	}
	return channels, nil
}

func (s *Store) GetLiveChannel(ctx context.Context, id int) (*model.LiveChannel, error) {
	var ch model.LiveChannel
	err := s.db.GetContext(ctx, &ch, `SELECT * FROM live_channels WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("getting live channel %d: %w", id, err)
	}
	return &ch, nil
}

func (s *Store) CreateLiveChannel(ctx context.Context, ch *model.LiveChannel) error {
	return s.db.QueryRowContext(ctx,
		`INSERT INTO live_channels (name, manifest_hls, manifest_dash, encoding_id) VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		ch.Name, ch.ManifestHLS, ch.ManifestDASH, ch.EncodingID,
	).Scan(&ch.ID, &ch.CreatedAt)
}
