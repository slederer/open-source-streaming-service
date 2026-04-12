import Link from "next/link";
import { Video, formatDuration } from "@/lib/api";

export default function VideoCard({ video }: { video: Video }) {
  const posterSrc =
    video.poster_url || "/placeholder-poster.svg";

  return (
    <Link href={`/video/${video.id}`} className="group block">
      <div className="relative aspect-video bg-gray-800 rounded-lg overflow-hidden">
        <img
          src={posterSrc}
          alt={video.title}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
        />
        <div className="absolute bottom-2 right-2 bg-black/80 text-white text-xs px-2 py-1 rounded">
          {formatDuration(video.duration)}
        </div>
        {video.license && (
          <div className="absolute top-2 left-2 bg-blue-600/90 text-white text-xs px-2 py-1 rounded">
            {video.license === "Public Domain" ? "PD" : video.license}
          </div>
        )}
      </div>
      <h3 className="mt-2 text-sm font-medium text-white group-hover:text-blue-400 transition-colors line-clamp-1">
        {video.title}
      </h3>
      <p className="text-xs text-gray-400 mt-1">
        {video.year} &middot; {video.attribution}
      </p>
    </Link>
  );
}
