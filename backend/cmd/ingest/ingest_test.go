package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalog(t *testing.T) {
	// Create a temp catalog file
	tmpDir := t.TempDir()
	catalogPath := filepath.Join(tmpDir, "catalog.json")

	catalogJSON := `[
		{
			"title": "Test Video",
			"description": "A test video",
			"source_url": "https://example.com/test.mp4",
			"duration": 120,
			"year": 2024,
			"license": "CC-BY 4.0",
			"attribution": "Test Author",
			"categories": ["animation"]
		},
		{
			"title": "Second Video",
			"description": "Another test",
			"source_url": "https://example.com/test2.mp4",
			"duration": 300,
			"year": 2023,
			"license": "Public Domain",
			"attribution": "Public",
			"categories": ["feature-film", "classic-cinema"]
		}
	]`

	if err := os.WriteFile(catalogPath, []byte(catalogJSON), 0644); err != nil {
		t.Fatalf("failed to write test catalog: %v", err)
	}

	entries, err := loadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("loadCatalog failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Title != "Test Video" {
		t.Errorf("expected title 'Test Video', got '%s'", entries[0].Title)
	}

	if entries[0].Duration != 120 {
		t.Errorf("expected duration 120, got %d", entries[0].Duration)
	}

	if len(entries[1].Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(entries[1].Categories))
	}
}

func TestLoadCatalog_FileNotFound(t *testing.T) {
	_, err := loadCatalog("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadCatalog_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := loadCatalog(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Big Buck Bunny", "big-buck-bunny"},
		{"Night of the Living Dead", "night-of-the-living-dead"},
		{"Agent 327: Operation Barbershop", "agent-327-operation-barbershop"},
		{"ISS Earth Time-Lapse 4K", "iss-earth-time-lapse-4k"},
		{"Metropolis", "metropolis"},
		{"  Spaces  ", "spaces"},
	}

	for _, tt := range tests {
		result := slugify(tt.input)
		if result != tt.expected {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
