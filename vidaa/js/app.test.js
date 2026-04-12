import { describe, it, expect, beforeEach } from "vitest";

// Mock DOM elements that app.js expects
globalThis.document = {
  querySelectorAll: () => [],
  getElementById: () => null,
  addEventListener: () => {},
};

const App = require("./app.js");

describe("App state machine", () => {
  beforeEach(() => {
    App._setVideos([
      { id: "1", title: "Video 1", duration: 120, year: 2020, license: "CC-BY", description: "Test" },
      { id: "2", title: "Video 2", duration: 300, year: 2021, license: "PD", description: "Test" },
      { id: "3", title: "Video 3", duration: 60, year: 2022, license: "CC0", description: "Test" },
      { id: "4", title: "Video 4", duration: 600, year: 2023, license: "CC-BY", description: "Test" },
      { id: "5", title: "Video 5", duration: 900, year: 2024, license: "PD", description: "Test" },
      { id: "6", title: "Video 6", duration: 180, year: 2025, license: "CC-BY", description: "Test" },
    ]);
    App._setFocusIndex(0);
    App.setState("gallery");
  });

  it("starts in gallery state", () => {
    expect(App.getState()).toBe("gallery");
  });

  it("navigates right in gallery", () => {
    App.handleKey(App.KEY.RIGHT);
    expect(App.getFocusIndex()).toBe(1);
  });

  it("navigates down in gallery", () => {
    App.handleKey(App.KEY.DOWN);
    expect(App.getFocusIndex()).toBe(5);
  });

  it("does not go left from index 0", () => {
    App.handleKey(App.KEY.LEFT);
    expect(App.getFocusIndex()).toBe(0);
  });

  it("does not go up from first row", () => {
    App.handleKey(App.KEY.UP);
    expect(App.getFocusIndex()).toBe(0);
  });

  it("transitions to detail on Enter", () => {
    const result = App.handleKey(App.KEY.ENTER);
    expect(result).toBe("detail");
  });

  it("transitions from detail to gallery on Back", () => {
    App.setState("detail");
    App._setSelectedVideo({ id: "1", title: "Test" });
    const result = App.handleKey(App.KEY.BACK);
    expect(result).toBe("gallery");
  });

  it("transitions from detail to gallery on Escape", () => {
    App.setState("detail");
    App._setSelectedVideo({ id: "1", title: "Test" });
    const result = App.handleKey(App.KEY.ESCAPE);
    expect(result).toBe("gallery");
  });

  it("transitions from player to detail on Back", () => {
    App.setState("player");
    // Mock PlayerManager
    globalThis.PlayerManager = { destroy: () => {} };
    const result = App.handleKey(App.KEY.BACK);
    expect(result).toBe("detail");
  });
});
