CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE videos (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    ai_description  TEXT NOT NULL DEFAULT '',
    duration        INTEGER NOT NULL DEFAULT 0,
    year            INTEGER NOT NULL DEFAULT 0,
    license         TEXT NOT NULL DEFAULT '',
    attribution     TEXT NOT NULL DEFAULT '',
    source_url      TEXT NOT NULL DEFAULT '',
    poster_url      TEXT NOT NULL DEFAULT '',
    thumbnail_urls  JSONB NOT NULL DEFAULT '[]',
    manifest_hls    TEXT NOT NULL DEFAULT '',
    manifest_dash   TEXT NOT NULL DEFAULT '',
    encoding_job_id TEXT NOT NULL DEFAULT '',
    drm_content_id  TEXT NOT NULL DEFAULT '',
    ad_breaks       JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE categories (
    id   SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL
);

CREATE TABLE video_categories (
    video_id    UUID REFERENCES videos(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES categories(id) ON DELETE CASCADE,
    PRIMARY KEY (video_id, category_id)
);

CREATE TABLE live_channels (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    manifest_hls  TEXT NOT NULL DEFAULT '',
    manifest_dash TEXT NOT NULL DEFAULT '',
    is_active     BOOLEAN NOT NULL DEFAULT true,
    encoding_id   TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_videos_status ON videos(status);
CREATE INDEX idx_video_categories_cat ON video_categories(category_id);

-- Seed default categories
INSERT INTO categories (name, slug) VALUES
    ('Animation', 'animation'),
    ('Short Film', 'short-film'),
    ('Feature Film', 'feature-film'),
    ('Classic Cinema', 'classic-cinema'),
    ('Science & Space', 'science-space'),
    ('Documentary', 'documentary');
