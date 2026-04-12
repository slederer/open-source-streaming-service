/**
 * Bitmovin Player wrapper for Vidaa HTML5 app.
 * @module player
 */
var PlayerManager = (function () {
  var player = null;
  var PLAYER_KEY = "";

  function setPlayerKey(key) {
    PLAYER_KEY = key;
  }

  function getPlayerKey() {
    return PLAYER_KEY;
  }

  /**
   * Build Bitmovin Player source config from playback info.
   */
  function buildSourceConfig(playbackInfo, title) {
    var source = { title: title || "Video" };

    // Prefer SSAI session URLs
    if (playbackInfo.session_url_hls) {
      source.hls = playbackInfo.session_url_hls;
    } else if (playbackInfo.manifest_hls) {
      source.hls = playbackInfo.manifest_hls;
    }

    if (playbackInfo.session_url_dash) {
      source.dash = playbackInfo.session_url_dash;
    } else if (playbackInfo.manifest_dash) {
      source.dash = playbackInfo.manifest_dash;
    }

    // DRM config
    if (playbackInfo.drm_token) {
      source.drm = {
        widevine: {
          LA_URL: playbackInfo.drm_widevine_url,
          headers: {
            "pallycon-customdata-v2": playbackInfo.drm_token,
          },
        },
      };
    }

    return source;
  }

  function init(containerId, playbackInfo, title) {
    if (typeof bitmovin === "undefined" || !bitmovin.player) {
      console.error("Bitmovin Player SDK not loaded");
      return null;
    }

    var container = document.getElementById(containerId);
    if (!container) return null;

    var config = {
      key: PLAYER_KEY,
      playback: { autoplay: true, muted: false },
      ui: false,
    };

    player = new bitmovin.player.Player(container, config);

    var source = buildSourceConfig(playbackInfo, title);
    player.load(source).catch(function (err) {
      console.error("Player load error:", err);
    });

    return player;
  }

  function destroy() {
    if (player) {
      player.destroy();
      player = null;
    }
  }

  function isPlaying() {
    return player && player.isPlaying();
  }

  // Export for testing
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      setPlayerKey: setPlayerKey,
      getPlayerKey: getPlayerKey,
      buildSourceConfig: buildSourceConfig,
      init: init,
      destroy: destroy,
      isPlaying: isPlaying,
    };
  }

  return {
    setPlayerKey: setPlayerKey,
    getPlayerKey: getPlayerKey,
    buildSourceConfig: buildSourceConfig,
    init: init,
    destroy: destroy,
    isPlaying: isPlaying,
  };
})();
