import { describe, it, expect } from "vitest";

const API = require("./api.js");

describe("API module", () => {
  it("has correct default base URL", () => {
    expect(API.getBaseURL()).toBe("http://localhost:8080");
  });

  it("allows setting base URL", () => {
    API.setBaseURL("https://example.com");
    expect(API.getBaseURL()).toBe("https://example.com");
    // Reset
    API.setBaseURL("http://localhost:8080");
  });

  describe("formatDuration", () => {
    it("formats seconds as m:ss", () => {
      expect(API.formatDuration(65)).toBe("1:05");
    });

    it("formats minutes only", () => {
      expect(API.formatDuration(120)).toBe("2:00");
    });

    it("formats hours", () => {
      expect(API.formatDuration(3661)).toBe("1:01:01");
    });

    it("formats zero", () => {
      expect(API.formatDuration(0)).toBe("0:00");
    });
  });
});
