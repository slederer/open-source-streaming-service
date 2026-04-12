import Link from "next/link";
import { Video, formatDuration } from "@/lib/api";

export default function VideoCard({ video }: { video: Video }) {
  // Generate a colorful gradient placeholder based on title hash
  const hash = video.title.split("").reduce((h, c) => c.charCodeAt(0) + ((h << 5) - h), 0);
  const hue = Math.abs(hash) % 360;
  const placeholderBg = `linear-gradient(135deg, hsl(${hue},60%,35%), hsl(${(hue + 60) % 360},60%,20%))`;

  return (
    <Link href={`/video/${video.id}`} className="group block">
      <div
        className="relative aspect-video rounded-lg overflow-hidden flex items-center justify-center"
        style={video.poster_url ? undefined : { background: placeholderBg }}
      >
        {video.poster_url ? (
          <img
            src={video.poster_url}
            alt={video.title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
        ) : (
          <div className="text-center px-4">
            <div className="text-4xl font-bold text-white/90 mb-1">
              {video.title.charAt(0)}
            </div>
            <div className="text-xs text-white/70 line-clamp-2">
              {video.title}
            </div>
          </div>
        )}
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
