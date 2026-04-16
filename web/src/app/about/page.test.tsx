import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import AboutPage from "./page";

describe("AboutPage", () => {
  it("renders the page title", () => {
    render(<AboutPage />);
    expect(screen.getByText("Behind the Build")).toBeDefined();
  });

  it("renders the three main sections", () => {
    render(<AboutPage />);
    expect(screen.getByText("What we built")).toBeDefined();
    expect(screen.getByText("Hurdles we hit (in order)")).toBeDefined();
    expect(
      screen.getByText(
        "What Bitmovin could do better for developers & AI agents"
      )
    ).toBeDefined();
  });

  it("renders the stat cards", () => {
    render(<AboutPage />);
    expect(screen.getByText("Commits")).toBeDefined();
    expect(screen.getByText("Tests passing")).toBeDefined();
    expect(screen.getByText("Titles in catalog")).toBeDefined();
    expect(screen.getByText("Client platforms")).toBeDefined();
  });

  it("calls out the blocker hurdle", () => {
    render(<AboutPage />);
    expect(
      screen.getByText("Bitmovin Encoding fails at 90% — no actionable error")
    ).toBeDefined();
  });

  it("includes the MCP server recommendation", () => {
    render(<AboutPage />);
    expect(
      screen.getByText("Ship an official Bitmovin MCP server")
    ).toBeDefined();
  });

  it("links to the GitHub repo", () => {
    render(<AboutPage />);
    const link = screen.getByText("Source on GitHub").closest("a");
    expect(link?.getAttribute("href")).toContain("github.com/slederer");
  });
});
