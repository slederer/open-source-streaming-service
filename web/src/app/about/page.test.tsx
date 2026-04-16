import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import AboutPage from "./page";

describe("AboutPage", () => {
  it("renders the hero heading", () => {
    render(<AboutPage />);
    expect(screen.getByText(/full streaming service/i)).toBeDefined();
    expect(screen.getByText(/built in one session/i)).toBeDefined();
  });

  it("renders the three main sections", () => {
    render(<AboutPage />);
    expect(screen.getByText("What we built")).toBeDefined();
    expect(screen.getByText("The hurdles")).toBeDefined();
    expect(screen.getByText("What Bitmovin could do better")).toBeDefined();
  });

  it("renders the stat labels", () => {
    render(<AboutPage />);
    expect(screen.getByText("Commits")).toBeDefined();
    expect(screen.getByText("Tests passing")).toBeDefined();
    expect(screen.getByText("Titles")).toBeDefined();
    expect(screen.getByText("Client platforms")).toBeDefined();
  });

  it("calls out the blocker hurdle", () => {
    render(<AboutPage />);
    expect(
      screen.getByText(/Bitmovin encoding fails at 90%/i)
    ).toBeDefined();
    // Has "Blocker" badge
    expect(screen.getByText("Blocker")).toBeDefined();
  });

  it("includes the MCP server recommendation", () => {
    render(<AboutPage />);
    expect(
      screen.getByText("Ship an official Bitmovin MCP server")
    ).toBeDefined();
  });

  it("links to the GitHub repo", () => {
    render(<AboutPage />);
    const link = screen
      .getByText("View source on GitHub")
      .closest("a");
    expect(link?.getAttribute("href")).toContain("github.com/slederer");
  });

  it("renders all four feedback groups", () => {
    render(<AboutPage />);
    expect(screen.getByText("Showstoppers")).toBeDefined();
    expect(screen.getByText("Major ergonomics")).toBeDefined();
    expect(screen.getByText("Streams API and Player")).toBeDefined();
    expect(screen.getByText("Operational")).toBeDefined();
  });
});
