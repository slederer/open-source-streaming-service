/**
 * API client for the Go backend.
 * @module api
 */
var API = (function () {
  var BASE_URL = "http://localhost:8080";

  function setBaseURL(url) {
    BASE_URL = url;
  }

  function getBaseURL() {
    return BASE_URL;
  }

  function fetchJSON(path) {
    return fetch(BASE_URL + path).then(function (res) {
      if (!res.ok) throw new Error("API error: " + res.status);
      return res.json();
    });
  }

  function getVideos(page, limit) {
    page = page || 1;
    limit = limit || 20;
    return fetchJSON("/api/videos?page=" + page + "&limit=" + limit);
  }

  function getVideo(id) {
    return fetchJSON("/api/videos/" + id);
  }

  function getPlaybackInfo(videoId) {
    return fetchJSON("/api/videos/" + videoId + "/playback");
  }

  function getLivePlaybackInfo(channelId) {
    return fetchJSON("/api/live/channels/" + channelId + "/playback");
  }

  function formatDuration(seconds) {
    var h = Math.floor(seconds / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var s = seconds % 60;
    if (h > 0) {
      return h + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
    }
    return m + ":" + String(s).padStart(2, "0");
  }

  // Export for testing
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      setBaseURL: setBaseURL,
      getBaseURL: getBaseURL,
      getVideos: getVideos,
      getVideo: getVideo,
      getPlaybackInfo: getPlaybackInfo,
      getLivePlaybackInfo: getLivePlaybackInfo,
      formatDuration: formatDuration,
    };
  }

  return {
    setBaseURL: setBaseURL,
    getBaseURL: getBaseURL,
    getVideos: getVideos,
    getVideo: getVideo,
    getPlaybackInfo: getPlaybackInfo,
    getLivePlaybackInfo: getLivePlaybackInfo,
    formatDuration: formatDuration,
  };
})();
