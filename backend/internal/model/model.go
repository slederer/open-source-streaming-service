package model

import (
	"encoding/json"
	"time"
)

type VideoStatus string

const (
	StatusPending  VideoStatus = "pending"
	StatusEncoding VideoStatus = "encoding"
	StatusReady    VideoStatus = "ready"
	StatusError    VideoStatus = "error"
)

type Video struct {
	ID             string          `db:"id" json:"id"`
	Title          string          `db:"title" json:"title"`
	Description    string          `db:"description" json:"description"`
	AIDescription  string          `db:"ai_description" json:"ai_description,omitempty"`
	Duration       int             `db:"duration" json:"duration"`
	Year           int             `db:"year" json:"year"`
	License        string          `db:"license" json:"license"`
	Attribution    string          `db:"attribution" json:"attribution"`
	SourceURL      string          `db:"source_url" json:"source_url,omitempty"`
	PosterURL      string          `db:"poster_url" json:"poster_url"`
	ThumbnailURLs  json.RawMessage `db:"thumbnail_urls" json:"thumbnail_urls"`
	ManifestHLS    string          `db:"manifest_hls" json:"manifest_hls,omitempty"`
	ManifestDASH   string          `db:"manifest_dash" json:"manifest_dash,omitempty"`
	EncodingJobID  string          `db:"encoding_job_id" json:"encoding_job_id,omitempty"`
	DRMContentID   string          `db:"drm_content_id" json:"drm_content_id,omitempty"`
	AdBreaks       json.RawMessage `db:"ad_breaks" json:"ad_breaks,omitempty"`
	Status         VideoStatus     `db:"status" json:"status"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
}

type Category struct {
	ID   int    `db:"id" json:"id"`
	Name string `db:"name" json:"name"`
	Slug string `db:"slug" json:"slug"`
}

type LiveChannel struct {
	ID           int       `db:"id" json:"id"`
	Name         string    `db:"name" json:"name"`
	ManifestHLS  string    `db:"manifest_hls" json:"manifest_hls,omitempty"`
	ManifestDASH string    `db:"manifest_dash" json:"manifest_dash,omitempty"`
	IsActive     bool      `db:"is_active" json:"is_active"`
	EncodingID   string    `db:"encoding_id" json:"encoding_id,omitempty"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
}

type VideoCategory struct {
	VideoID    string `db:"video_id"`
	CategoryID int    `db:"category_id"`
}

// VideoWithCategories is used for API responses that include category info.
type VideoWithCategories struct {
	Video
	Categories []Category `json:"categories,omitempty"`
}

// PlaybackInfo is returned by the playback endpoint.
type PlaybackInfo struct {
	ManifestHLS  string `json:"manifest_hls"`
	ManifestDASH string `json:"manifest_dash"`
	DRMToken     string `json:"drm_token,omitempty"`
	SessionURL   string `json:"session_url,omitempty"`
}

// PaginatedResponse wraps a list with pagination metadata.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	TotalCount int         `json:"total_count"`
}
