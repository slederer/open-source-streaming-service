/**
 * Main application logic for Vidaa HTML5 TV app.
 * State machine: gallery → detail → player
 * D-pad navigation via arrow keys + Enter + Back.
 * @module app
 */
var App = (function () {
  // State
  var state = "gallery"; // gallery | detail | player
  var videos = [];
  var focusIndex = 0;
  var columns = 5;
  var selectedVideo = null;

  // Key codes
  var KEY = {
    LEFT: 37,
    UP: 38,
    RIGHT: 39,
    DOWN: 40,
    ENTER: 13,
    BACK: 10009,       // Tizen/Vidaa Back button
    BACK_ALT: 8,       // Backspace as fallback
    ESCAPE: 27,        // Escape as fallback
  };

  function getState() {
    return state;
  }

  function getVideos() {
    return videos;
  }

  function getFocusIndex() {
    return focusIndex;
  }

  function setState(newState) {
    state = newState;
    // Update view visibility
    var views = document.querySelectorAll(".view");
    for (var i = 0; i < views.length; i++) {
      views[i].classList.remove("active");
    }
    var viewId = newState + "-view";
    var view = document.getElementById(viewId);
    if (view) view.classList.add("active");
  }

  function setFocus(index) {
    if (index < 0 || index >= videos.length) return;
    // Remove old focus
    var cards = document.querySelectorAll(".card");
    for (var i = 0; i < cards.length; i++) {
      cards[i].classList.remove("focused");
    }
    focusIndex = index;
    if (cards[focusIndex]) {
      cards[focusIndex].classList.add("focused");
      cards[focusIndex].scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  function handleKey(keyCode) {
    if (state === "gallery") {
      return handleGalleryKey(keyCode);
    } else if (state === "detail") {
      return handleDetailKey(keyCode);
    } else if (state === "player") {
      return handlePlayerKey(keyCode);
    }
    return state;
  }

  function handleGalleryKey(keyCode) {
    switch (keyCode) {
      case KEY.LEFT:
        if (focusIndex % columns > 0) setFocus(focusIndex - 1);
        break;
      case KEY.RIGHT:
        if (focusIndex % columns < columns - 1 && focusIndex + 1 < videos.length)
          setFocus(focusIndex + 1);
        break;
      case KEY.UP:
        if (focusIndex >= columns) setFocus(focusIndex - columns);
        break;
      case KEY.DOWN:
        if (focusIndex + columns < videos.length) setFocus(focusIndex + columns);
        break;
      case KEY.ENTER:
        selectedVideo = videos[focusIndex];
        showDetail(selectedVideo);
        setState("detail");
        break;
    }
    return state;
  }

  function handleDetailKey(keyCode) {
    switch (keyCode) {
      case KEY.ENTER:
        playVideo(selectedVideo);
        setState("player");
        break;
      case KEY.BACK:
      case KEY.BACK_ALT:
      case KEY.ESCAPE:
        setState("gallery");
        break;
    }
    return state;
  }

  function handlePlayerKey(keyCode) {
    switch (keyCode) {
      case KEY.BACK:
      case KEY.BACK_ALT:
      case KEY.ESCAPE:
        PlayerManager.destroy();
        setState("detail");
        break;
    }
    return state;
  }

  function renderGallery() {
    var grid = document.getElementById("video-grid");
    if (!grid) return;
    grid.innerHTML = "";

    videos.forEach(function (video, i) {
      var card = document.createElement("div");
      card.className = "card" + (i === focusIndex ? " focused" : "");
      card.innerHTML =
        '<div class="card-thumb">' +
          (video.poster_url
            ? '<img src="' + video.poster_url + '" alt="">'
            : video.title.charAt(0)) +
        "</div>" +
        '<div class="card-duration">' + API.formatDuration(video.duration) + "</div>" +
        '<div class="card-title">' + video.title + "</div>" +
        '<div class="card-meta">' + video.year + " · " + video.license + "</div>";

      card.onclick = function () {
        focusIndex = i;
        selectedVideo = video;
        showDetail(video);
        setState("detail");
      };

      grid.appendChild(card);
    });
  }

  function showDetail(video) {
    var title = document.getElementById("detail-title");
    var meta = document.getElementById("detail-meta");
    var desc = document.getElementById("detail-description");

    if (title) title.textContent = video.title;
    if (meta) meta.textContent = video.year + " · " + API.formatDuration(video.duration) + " · " + video.license;
    if (desc) desc.textContent = video.ai_description || video.description;
  }

  function playVideo(video) {
    API.getPlaybackInfo(video.id).then(function (info) {
      PlayerManager.init("player-container", info, video.title);
    }).catch(function (err) {
      console.error("Failed to get playback info:", err);
    });
  }

  function init() {
    // Load videos
    API.getVideos(1, 20).then(function (resp) {
      videos = resp.data || [];
      renderGallery();
      setFocus(0);
    }).catch(function (err) {
      console.error("Failed to load videos:", err);
    });

    // Key handler
    document.addEventListener("keydown", function (e) {
      handleKey(e.keyCode);
    });
  }

  // Export for testing
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      getState: getState,
      getVideos: getVideos,
      getFocusIndex: getFocusIndex,
      setState: setState,
      setFocus: setFocus,
      handleKey: handleKey,
      handleGalleryKey: handleGalleryKey,
      handleDetailKey: handleDetailKey,
      handlePlayerKey: handlePlayerKey,
      init: init,
      KEY: KEY,
      // Internal setters for testing
      _setVideos: function (v) { videos = v; },
      _setFocusIndex: function (i) { focusIndex = i; },
      _setSelectedVideo: function (v) { selectedVideo = v; },
    };
  }

  return {
    getState: getState,
    getVideos: getVideos,
    getFocusIndex: getFocusIndex,
    setState: setState,
    handleKey: handleKey,
    init: init,
    KEY: KEY,
  };
})();

// Auto-init when DOM is ready (only in browser)
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", function () {
    App.init();
  });
}
