import { getVideo } from "@/lib/api";
import { formatDuration } from "@/lib/api";
import Link from "next/link";

export default async function VideoDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let video;
  try {
    video = await getVideo(id);
  } catch {
    return (
      <div className="text-center py-20">
        <p className="text-gray-400">Video not found.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Poster */}
      <div className="relative aspect-video bg-gray-800 rounded-xl overflow-hidden mb-6">
        {video.poster_url ? (
          <img
            src={video.poster_url}
            alt={video.title}
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center text-gray-600">
            No poster available
          </div>
        )}
        <Link
          href={`/player/${video.id}`}
          className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 hover:opacity-100 transition-opacity"
        >
          <div className="w-20 h-20 rounded-full bg-white/90 flex items-center justify-center">
            <span className="text-black text-3xl ml-1">&#9654;</span>
          </div>
        </Link>
      </div>

      {/* Info */}
      <h1 className="text-3xl font-bold text-white mb-2">{video.title}</h1>

      <div className="flex gap-4 text-sm text-gray-400 mb-4">
        <span>{video.year}</span>
        <span>{formatDuration(video.duration)}</span>
        <span className="text-blue-400">{video.license}</span>
        {video.status === "ready" && (
          <span className="text-green-400">Ready</span>
        )}
        {video.status === "encoding" && (
          <span className="text-yellow-400">Encoding...</span>
        )}
      </div>

      <p className="text-gray-300 text-lg mb-6">
        {video.ai_description || video.description}
      </p>

      {video.description && video.ai_description && (
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-gray-400 mb-2">
            Original Description
          </h3>
          <p className="text-gray-400">{video.description}</p>
        </div>
      )}

      <div className="flex gap-4 mb-8">
        <Link
          href={`/player/${video.id}`}
          className="bg-white text-black font-semibold px-8 py-3 rounded-lg hover:bg-gray-200 transition-colors"
        >
          &#9654; Play
        </Link>
      </div>

      {/* Metadata */}
      <div className="border-t border-gray-800 pt-6 grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-gray-500">Attribution</span>
          <p className="text-gray-300">{video.attribution}</p>
        </div>
        <div>
          <span className="text-gray-500">License</span>
          <p className="text-gray-300">{video.license}</p>
        </div>
        {video.categories && video.categories.length > 0 && (
          <div>
            <span className="text-gray-500">Categories</span>
            <div className="flex gap-2 mt-1">
              {video.categories.map((cat) => (
                <Link
                  key={cat.id}
                  href={`/browse?category=${cat.slug}`}
                  className="text-blue-400 hover:text-blue-300"
                >
                  {cat.name}
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Thumbnails */}
      {video.thumbnail_urls && video.thumbnail_urls.length > 0 && (
        <div className="mt-8">
          <h3 className="text-lg font-semibold text-white mb-4">
            Scene Thumbnails
          </h3>
          <div className="grid grid-cols-4 gap-2">
            {video.thumbnail_urls.map((url, i) => (
              <img
                key={i}
                src={url}
                alt={`Scene ${i + 1}`}
                className="rounded aspect-video object-cover bg-gray-800"
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
