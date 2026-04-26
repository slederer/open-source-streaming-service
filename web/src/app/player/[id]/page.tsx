"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import HlsPlayer from "@/components/HlsPlayer";
import type { PlaybackInfo } from "@/lib/api";

const API_BASE = "";

export default function PlayerPage() {
  const params = useParams();
  const id = params.id as string;
  const [playbackInfo, setPlaybackInfo] = useState<PlaybackInfo | null>(null);
  const [title, setTitle] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const [videoRes, playbackRes] = await Promise.all([
          fetch(`${API_BASE}/api/videos/${id}`),
          fetch(`${API_BASE}/api/videos/${id}/playback`),
        ]);

        if (!videoRes.ok || !playbackRes.ok) {
          setError("Failed to load video");
          return;
        }

        const video = await videoRes.json();
        const playback: PlaybackInfo = await playbackRes.json();

        setTitle(video.title);
        setPlaybackInfo(playback);
      } catch {
        setError("Failed to connect to API");
      }
    }

    load();
  }, [id]);

  if (error) {
    return (
      <div className="text-center py-20">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  if (!playbackInfo) {
    return (
      <div className="text-center py-20">
        <div className="animate-pulse text-gray-400">Loading player...</div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto">
      {playbackInfo.stream_id ? (
        // Bitmovin Streams: use iframe embed (always works, includes UI + analytics)
        <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
          <iframe
            src={`https://streams.bitmovin.com/${playbackInfo.stream_id}/embed`}
            className="w-full h-full border-0"
            allow="autoplay; fullscreen"
            allowFullScreen
          />
        </div>
      ) : (
        // Fallback: HLS.js player (works on all browsers)
        <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
          <HlsPlayer src={playbackInfo.manifest_hls} />
        </div>
      )}
      <h2 className="text-xl font-bold text-white mt-4">{title}</h2>
    </div>
  );
}
