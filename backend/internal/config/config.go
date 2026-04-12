package config

import (
	"os"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port     string
	DBUrl    string
	APIBase  string

	// Bitmovin
	BitmovinAPIKey      string
	BitmovinOrgID       string
	BitmovinPlayerKey   string
	BitmovinAnalyticsKey string

	// Google OAuth
	GoogleClientID     string
	GoogleClientSecret string

	// AWS
	AWSRegion        string
	S3InputBucket    string
	S3OutputBucket   string
	S3ThumbnailBucket string
	CloudFrontDomain string

	// MediaTailor
	MediaTailorVODEndpoint  string
	MediaTailorLiveEndpoint string
	ADDecisionServerURL     string

	// DoveRunner DRM (formerly PallyCon)
	PallyConSiteID    string
	PallyConSiteKey   string
	PallyConAccessKey string

	// Live
	BitmovinLiveStreamKey  string
	BitmovinLiveEncodingID string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:    getEnv("PORT", "8080"),
		DBUrl:   getEnv("DATABASE_URL", "postgres://streaming:streaming@localhost:5432/streaming?sslmode=disable"),
		APIBase: getEnv("API_BASE_URL", "http://localhost:8080"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),

		BitmovinAPIKey:       os.Getenv("BITMOVIN_API_KEY"),
		BitmovinOrgID:        os.Getenv("BITMOVIN_ORG_ID"),
		BitmovinPlayerKey:    os.Getenv("BITMOVIN_PLAYER_KEY"),
		BitmovinAnalyticsKey: os.Getenv("BITMOVIN_ANALYTICS_KEY"),

		AWSRegion:         getEnv("AWS_REGION", "us-east-1"),
		S3InputBucket:     getEnv("S3_INPUT_BUCKET", "oss-streaming-input"),
		S3OutputBucket:    getEnv("S3_OUTPUT_BUCKET", "oss-streaming-output"),
		S3ThumbnailBucket: getEnv("S3_THUMBNAIL_BUCKET", "oss-streaming-thumbnails"),
		CloudFrontDomain:  os.Getenv("CLOUDFRONT_DOMAIN"),

		MediaTailorVODEndpoint:  os.Getenv("MEDIATAILOR_VOD_ENDPOINT"),
		MediaTailorLiveEndpoint: os.Getenv("MEDIATAILOR_LIVE_ENDPOINT"),
		ADDecisionServerURL:     os.Getenv("AD_DECISION_SERVER_URL"),

		PallyConSiteID:    os.Getenv("PALLYCON_SITE_ID"),
		PallyConSiteKey:   os.Getenv("PALLYCON_SITE_KEY"),
		PallyConAccessKey: os.Getenv("PALLYCON_ACCESS_KEY"),

		BitmovinLiveStreamKey:  os.Getenv("BITMOVIN_LIVE_STREAM_KEY"),
		BitmovinLiveEncodingID: os.Getenv("BITMOVIN_LIVE_ENCODING_ID"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
