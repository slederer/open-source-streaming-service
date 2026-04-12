import { describe, it, expect } from "vitest";

const PlayerManager = require("./player.js");

describe("PlayerManager", () => {
  it("allows setting player key", () => {
    PlayerManager.setPlayerKey("test-key-123");
    expect(PlayerManager.getPlayerKey()).toBe("test-key-123");
  });

  describe("buildSourceConfig", () => {
    it("uses SSAI session URLs when available", () => {
      const info = {
        manifest_hls: "https://cdn.example.com/manifest.m3u8",
        manifest_dash: "https://cdn.example.com/manifest.mpd",
        session_url_hls: "https://mediatailor.example.com/session/manifest.m3u8",
        session_url_dash: "https://mediatailor.example.com/session/manifest.mpd",
      };

      const config = PlayerManager.buildSourceConfig(info, "Test Video");

      expect(config.hls).toBe("https://mediatailor.example.com/session/manifest.m3u8");
      expect(config.dash).toBe("https://mediatailor.example.com/session/manifest.mpd");
      expect(config.title).toBe("Test Video");
    });

    it("falls back to direct manifests without SSAI", () => {
      const info = {
        manifest_hls: "https://cdn.example.com/manifest.m3u8",
        manifest_dash: "https://cdn.example.com/manifest.mpd",
      };

      const config = PlayerManager.buildSourceConfig(info, "Direct");

      expect(config.hls).toBe("https://cdn.example.com/manifest.m3u8");
      expect(config.dash).toBe("https://cdn.example.com/manifest.mpd");
    });

    it("includes DRM config when token is present", () => {
      const info = {
        manifest_hls: "https://cdn.example.com/manifest.m3u8",
        drm_token: "test-token",
        drm_widevine_url: "https://license.pallycon.com/ri/widevineLicense",
      };

      const config = PlayerManager.buildSourceConfig(info);

      expect(config.drm).toBeDefined();
      expect(config.drm.widevine.LA_URL).toBe("https://license.pallycon.com/ri/widevineLicense");
      expect(config.drm.widevine.headers["pallycon-customdata-v2"]).toBe("test-token");
    });

    it("omits DRM config when no token", () => {
      const info = {
        manifest_hls: "https://cdn.example.com/manifest.m3u8",
      };

      const config = PlayerManager.buildSourceConfig(info);

      expect(config.drm).toBeUndefined();
    });
  });
});
