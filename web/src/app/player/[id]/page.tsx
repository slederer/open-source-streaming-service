import { getVideo, getPlaybackInfo } from "@/lib/api";
import type { PlaybackInfo } from "@/lib/api";
import HlsPlayerClient from "./HlsPlayerClient";

export default async function PlayerPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let title = "";
  let playbackInfo: PlaybackInfo | null = null;

  try {
    const [video, playback] = await Promise.all([
      getVideo(id),
      getPlaybackInfo(id),
    ]);
    title = video.title;
    playbackInfo = playback;
  } catch {
    return (
      <div className="text-center py-20">
        <p className="text-red-400">Failed to load video</p>
      </div>
    );
  }

  if (!playbackInfo) {
    return (
      <div className="text-center py-20">
        <p className="text-gray-400">Video not available</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto">
      {playbackInfo.stream_id ? (
        <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
          <iframe
            src={`https://streams.bitmovin.com/${playbackInfo.stream_id}/embed`}
            className="w-full h-full border-0"
            allow="autoplay; fullscreen"
            allowFullScreen
          />
        </div>
      ) : (
        <div className="w-full aspect-video bg-black rounded-lg overflow-hidden">
          <HlsPlayerClient src={playbackInfo.manifest_hls} />
        </div>
      )}
      <h2 className="text-xl font-bold text-white mt-4">{title}</h2>
    </div>
  );
}
