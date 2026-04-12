package handler

import (
	"fmt"
	"net/http"
)

// MockVAST handles GET /api/ads/vast
// Returns a VAST XML response with a mock pre-roll ad using catalog content.
func (h *Handler) MockVAST(w http.ResponseWriter, r *http.Request) {
	// Use a segment of Big Buck Bunny as the mock ad creative
	adMediaURL := fmt.Sprintf("https://%s/ads/bbb-preroll.mp4", h.Config.CloudFrontDomain)

	vast := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<VAST version="3.0">
  <Ad id="mock-preroll-1">
    <InLine>
      <AdSystem>OSS Streaming Mock ADS</AdSystem>
      <AdTitle>Open Source Streaming - Demo Ad</AdTitle>
      <Impression><![CDATA[%s/api/ads/impression?ad=mock-preroll-1]]></Impression>
      <Creatives>
        <Creative>
          <Linear>
            <Duration>00:00:15</Duration>
            <MediaFiles>
              <MediaFile delivery="progressive" type="video/mp4" width="1920" height="1080" bitrate="3000">
                <![CDATA[%s]]>
              </MediaFile>
            </MediaFiles>
          </Linear>
        </Creative>
      </Creatives>
    </InLine>
  </Ad>
</VAST>`, h.Config.APIBase, adMediaURL)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, vast)
}

// AdImpression handles GET /api/ads/impression (tracking pixel)
func (h *Handler) AdImpression(w http.ResponseWriter, r *http.Request) {
	// Log the impression (in production, write to analytics)
	w.WriteHeader(http.StatusNoContent)
}
