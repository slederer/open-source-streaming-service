import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import VideoCard from "./VideoCard";
import type { Video } from "@/lib/api";

const mockVideo: Video = {
  id: "test-id",
  title: "Big Buck Bunny",
  description: "A test video",
  ai_description: "",
  duration: 596,
  year: 2008,
  license: "CC-BY 4.0",
  attribution: "Blender Foundation",
  poster_url: "",
  thumbnail_urls: [],
  manifest_hls: "",
  manifest_dash: "",
  status: "ready",
  created_at: "2024-01-01T00:00:00Z",
};

describe("VideoCard", () => {
  it("renders video title", () => {
    render(<VideoCard video={mockVideo} />);
    expect(screen.getByText("Big Buck Bunny")).toBeDefined();
  });

  it("renders duration badge", () => {
    render(<VideoCard video={mockVideo} />);
    expect(screen.getByText("9:56")).toBeDefined();
  });

  it("renders year and attribution", () => {
    render(<VideoCard video={mockVideo} />);
    const text = screen.getByText(/2008/);
    expect(text).toBeDefined();
  });

  it("renders license badge", () => {
    render(<VideoCard video={mockVideo} />);
    expect(screen.getByText("CC-BY 4.0")).toBeDefined();
  });

  it("renders public domain badge as PD", () => {
    const pdVideo = { ...mockVideo, license: "Public Domain" };
    render(<VideoCard video={pdVideo} />);
    expect(screen.getByText("PD")).toBeDefined();
  });

  it("links to video detail page", () => {
    render(<VideoCard video={mockVideo} />);
    const link = screen.getByRole("link");
    expect(link.getAttribute("href")).toBe("/video/test-id");
  });
});
