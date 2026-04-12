"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PlayerWrapper from "@/components/PlayerWrapper";
import type { PlaybackInfo } from "@/lib/api";

const API_BASE = "";
const PLAYER_KEY = process.env.NEXT_PUBLIC_BITMOVIN_PLAYER_KEY || "";
const ANALYTICS_KEY = process.env.NEXT_PUBLIC_BITMOVIN_ANALYTICS_KEY || "";

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
        const playback = await playbackRes.json();

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
        <p className="text-gray-400">Loading player...</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto">
      <PlayerWrapper
        playbackInfo={playbackInfo}
        playerKey={PLAYER_KEY}
        analyticsKey={ANALYTICS_KEY}
        title={title}
      />
      <h2 className="text-xl font-bold text-white mt-4">{title}</h2>
    </div>
  );
}
