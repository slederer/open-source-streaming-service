"use client";

import { useEffect, useRef } from "react";
import type { PlaybackInfo } from "@/lib/api";

interface PlayerWrapperProps {
  playbackInfo: PlaybackInfo;
  playerKey: string;
  analyticsKey?: string;
  title?: string;
  streamId?: string; // Bitmovin Streams ID (preferred if set)
}

export default function PlayerWrapper({
  playbackInfo,
  playerKey,
  analyticsKey,
  title,
  streamId,
}: PlayerWrapperProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const playerRef = useRef<unknown>(null);

  // If we have a Bitmovin Streams ID, use the web component (simpler + thumbnails + posters)
  useEffect(() => {
    if (!streamId) return;

    // Load the Bitmovin Streams web component script once
    const existing = document.querySelector(
      'script[src="https://streams.bitmovin.com/js/component.js"]'
    );
    if (!existing) {
      const script = document.createElement("script");
      script.type = "module";
      script.src = "https://streams.bitmovin.com/js/component.js";
      document.head.appendChild(script);
    }
  }, [streamId]);

  // If no streamId, fall back to the raw Player SDK with manifest URLs
  useEffect(() => {
    if (streamId) return; // Use web component path instead
    let destroyed = false;

    async function initPlayer() {
      if (!containerRef.current || destroyed) return;

      const { Player } = await import("bitmovin-player");
      if (destroyed) return;

      const playerConfig = {
        key: playerKey,
        playback: { autoplay: true, muted: false },
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const player = new Player(containerRef.current, playerConfig as any);
      playerRef.current = player;

      const sourceConfig: Record<string, unknown> = { title: title || "Video" };

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

      if (playbackInfo.drm_token) {
        sourceConfig.drm = {
          widevine: {
            LA_URL: playbackInfo.drm_widevine_url,
            headers: { "pallycon-customdata-v2": playbackInfo.drm_token },
          },
          fairplay: {
            LA_URL: playbackInfo.drm_fairplay_url,
            certificateURL: playbackInfo.drm_fairplay_cert_url,
            headers: { "pallycon-customdata-v2": playbackInfo.drm_token },
          },
        };
      }

      await player.load(sourceConfig);

      if (analyticsKey && !destroyed) {
        console.log("Bitmovin Analytics key:", analyticsKey);
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
  }, [playbackInfo, playerKey, analyticsKey, title, streamId]);

  // Use Bitmovin Streams web component if we have a stream ID
  if (streamId) {
    return (
      <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
        {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
        {/* @ts-expect-error - web component */}
        <bitmovin-stream stream-id={streamId} autoplay="true" />
      </div>
    );
  }

  // Otherwise, raw Player SDK with manifest URLs
  return (
    <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
      <div ref={containerRef} className="w-full h-full" />
    </div>
  );
}
