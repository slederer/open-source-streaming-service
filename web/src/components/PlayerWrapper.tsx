"use client";

import { useEffect, useRef } from "react";
import type { PlaybackInfo } from "@/lib/api";

interface PlayerWrapperProps {
  playbackInfo: PlaybackInfo;
  playerKey: string;
  analyticsKey?: string;
  title?: string;
}

export default function PlayerWrapper({
  playbackInfo,
  playerKey,
  analyticsKey,
  title,
}: PlayerWrapperProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const playerRef = useRef<unknown>(null);

  useEffect(() => {
    let destroyed = false;

    async function initPlayer() {
      if (!containerRef.current || destroyed) return;

      // Dynamic import to avoid SSR issues
      const { Player } = await import("bitmovin-player");

      if (destroyed) return;

      const playerConfig = {
        key: playerKey,
        playback: { autoplay: true, muted: false },
        ui: false,
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const player = new Player(containerRef.current, playerConfig as any);
      playerRef.current = player;

      // Configure source with DRM if available
      const sourceConfig: Record<string, unknown> = {
        title: title || "Video",
      };

      // Prefer MediaTailor session URLs (SSAI) over direct manifests
      if (playbackInfo.session_url_hls) {
        sourceConfig.hls = playbackInfo.session_url_hls;
      } else if (playbackInfo.manifest_hls) {
        sourceConfig.hls = playbackInfo.manifest_hls;
      }

      if (playbackInfo.session_url_dash) {
        sourceConfig.dash = playbackInfo.session_url_dash;
      } else if (playbackInfo.manifest_dash) {
        sourceConfig.dash = playbackInfo.manifest_dash;
      }

      // Add DRM configuration if token is available
      if (playbackInfo.drm_token) {
        sourceConfig.drm = {
          widevine: {
            LA_URL: playbackInfo.drm_widevine_url,
            headers: {
              "pallycon-customdata-v2": playbackInfo.drm_token,
            },
          },
          fairplay: {
            LA_URL: playbackInfo.drm_fairplay_url,
            certificateURL: playbackInfo.drm_fairplay_cert_url,
            headers: {
              "pallycon-customdata-v2": playbackInfo.drm_token,
            },
          },
        };
      }

      await player.load(sourceConfig);

      // Analytics: Bitmovin Analytics is configured via the player config
      // when the bitmovin-analytics package is installed. For now, log readiness.
      if (analyticsKey && !destroyed) {
        console.log("Bitmovin Analytics configured with key:", analyticsKey);
      }
    }

    initPlayer();

    return () => {
      destroyed = true;
      if (playerRef.current) {
        (playerRef.current as { destroy: () => void }).destroy();
        playerRef.current = null;
      }
    };
  }, [playbackInfo, playerKey, analyticsKey, title]);

  return (
    <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
}
