import Link from "next/link";
import { Video } from "@/lib/api";

export default function Hero({ video }: { video: Video }) {
  return (
    <div className="relative h-[60vh] min-h-[400px] mb-8 rounded-xl overflow-hidden">
      <div
        className="absolute inset-0 bg-cover bg-center"
        style={{
          backgroundImage: video.poster_url
            ? `url(${video.poster_url})`
            : "linear-gradient(135deg, #1a1a2e, #16213e)",
        }}
      />
      <div className="absolute inset-0 bg-gradient-to-t from-gray-950 via-gray-950/60 to-transparent" />
      <div className="absolute bottom-0 left-0 right-0 p-8">
        <h1 className="text-4xl font-bold text-white mb-2">{video.title}</h1>
        <p className="text-gray-300 text-lg max-w-2xl mb-4 line-clamp-2">
          {video.ai_description || video.description}
        </p>
        <div className="flex gap-4">
          <Link
            href={`/player/${video.id}`}
            className="bg-white text-black font-semibold px-6 py-3 rounded-lg hover:bg-gray-200 transition-colors"
          >
            &#9654; Play
          </Link>
          <Link
            href={`/video/${video.id}`}
            className="bg-gray-600/80 text-white font-semibold px-6 py-3 rounded-lg hover:bg-gray-500/80 transition-colors"
          >
            More Info
          </Link>
        </div>
      </div>
    </div>
  );
}
