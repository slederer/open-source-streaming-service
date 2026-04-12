import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import CategoryRow from "./CategoryRow";
import type { Video } from "@/lib/api";

const mockVideos: Video[] = [
  {
    id: "1",
    title: "Video One",
    description: "",
    ai_description: "",
    duration: 120,
    year: 2020,
    license: "CC-BY",
    attribution: "Author",
    poster_url: "",
    thumbnail_urls: [],
    manifest_hls: "",
    manifest_dash: "",
    status: "ready",
    created_at: "2024-01-01T00:00:00Z",
  },
  {
    id: "2",
    title: "Video Two",
    description: "",
    ai_description: "",
    duration: 300,
    year: 2021,
    license: "PD",
    attribution: "Author 2",
    poster_url: "",
    thumbnail_urls: [],
    manifest_hls: "",
    manifest_dash: "",
    status: "ready",
    created_at: "2024-01-01T00:00:00Z",
  },
];

describe("CategoryRow", () => {
  it("renders category title", () => {
    render(<CategoryRow title="Animation" videos={mockVideos} />);
    expect(screen.getByText("Animation")).toBeDefined();
  });

  it("renders all video cards", () => {
    render(<CategoryRow title="Test" videos={mockVideos} />);
    // Titles appear both in placeholder and heading — just check they exist
    expect(screen.getAllByText("Video One").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Video Two").length).toBeGreaterThan(0);
  });

  it("returns null for empty videos", () => {
    const { container } = render(
      <CategoryRow title="Empty" videos={[]} />
    );
    expect(container.innerHTML).toBe("");
  });
});
