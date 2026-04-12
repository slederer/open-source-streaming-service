import Hero from "@/components/Hero";
import CategoryRow from "@/components/CategoryRow";
import { getVideos, getCategories, getLiveChannels } from "@/lib/api";
import Link from "next/link";

export default async function Home() {
  let videos, categories, liveChannels;

  try {
    const [videosResp, cats, live] = await Promise.all([
      getVideos(1, 50),
      getCategories(),
      getLiveChannels(),
    ]);
    videos = videosResp.data;
    categories = cats;
    liveChannels = live;
  } catch {
    return (
      <div className="text-center py-20">
        <h1 className="text-2xl font-bold text-white mb-4">
          Welcome to OSStream
        </h1>
        <p className="text-gray-400">
          Unable to connect to the API. Make sure the backend is running on{" "}
          <code className="text-blue-400">localhost:8080</code>.
        </p>
      </div>
    );
  }

  // Prefer a video with an actual poster for the hero
  const featured = videos?.find((v) => v.poster_url) || videos?.[0];
  // Show videos with posters first in the gallery
  const sortedVideos = videos ? [...videos].sort((a, b) => {
    if (!!a.poster_url === !!b.poster_url) return 0;
    return a.poster_url ? -1 : 1;
  }) : [];
  const activeLive = liveChannels?.filter((ch) => ch.is_active) || [];

  return (
    <div>
      {featured && <Hero video={featured} />}

      {activeLive.length > 0 && (
        <div className="mb-8 p-4 bg-red-900/30 border border-red-800 rounded-lg">
          <div className="flex items-center gap-3">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
            </span>
            <span className="font-semibold text-red-300">Live Now</span>
            {activeLive.map((ch) => (
              <Link
                key={ch.id}
                href={`/player/live/${ch.id}`}
                className="text-white hover:text-red-300 transition-colors"
              >
                {ch.name}
              </Link>
            ))}
          </div>
        </div>
      )}

      {sortedVideos.length > 0 && (
        <CategoryRow title="All Videos" videos={sortedVideos} />
      )}
    </div>
  );
}
