import { describe, it, expect } from "vitest";
import { formatDuration } from "./api";

describe("formatDuration", () => {
  it("formats seconds as m:ss", () => {
    expect(formatDuration(65)).toBe("1:05");
  });

  it("formats minutes only", () => {
    expect(formatDuration(120)).toBe("2:00");
  });

  it("formats hours", () => {
    expect(formatDuration(3661)).toBe("1:01:01");
  });

  it("formats zero", () => {
    expect(formatDuration(0)).toBe("0:00");
  });

  it("formats large duration", () => {
    expect(formatDuration(8700)).toBe("2:25:00");
  });
});
