"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PlayerWrapper from "@/components/PlayerWrapper";
import type { PlaybackInfo } from "@/lib/api";

const API_BASE = "";
const PLAYER_KEY = process.env.NEXT_PUBLIC_BITMOVIN_PLAYER_KEY || "";
const ANALYTICS_KEY = process.env.NEXT_PUBLIC_BITMOVIN_ANALYTICS_KEY || "";

export default function LivePlayerPage() {
  const params = useParams();
  const id = params.id as string;
  const [playbackInfo, setPlaybackInfo] = useState<PlaybackInfo | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(
          `${API_BASE}/api/live/channels/${id}/playback`
        );
        if (!res.ok) {
          setError("Failed to load live channel");
          return;
        }
        setPlaybackInfo(await res.json());
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
        <p className="text-gray-400">Loading live stream...</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-4">
        <span className="relative flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
        </span>
        <h2 className="text-xl font-bold text-white">Live</h2>
      </div>
      <PlayerWrapper
        playbackInfo={playbackInfo}
        playerKey={PLAYER_KEY}
        analyticsKey={ANALYTICS_KEY}
        title="Live Channel"
      />
    </div>
  );
}
