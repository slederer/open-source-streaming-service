import VideoCard from "@/components/VideoCard";
import { getVideos, getCategories } from "@/lib/api";
import Link from "next/link";

export default async function BrowsePage({
  searchParams,
}: {
  searchParams: Promise<{ category?: string; page?: string }>;
}) {
  const params = await searchParams;
  const category = params.category || "";
  const page = parseInt(params.page || "1", 10);

  let videos, totalCount, categories;

  try {
    const [videosResp, cats] = await Promise.all([
      getVideos(page, 20, category || undefined),
      getCategories(),
    ]);
    videos = videosResp.data;
    totalCount = videosResp.total_count;
    categories = cats;
  } catch {
    return (
      <div className="text-center py-20">
        <p className="text-gray-400">Unable to load videos.</p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-3xl font-bold text-white mb-6">Browse</h1>

      {/* Category filters */}
      <div className="flex gap-2 mb-8 flex-wrap">
        <Link
          href="/browse"
          className={`px-4 py-2 rounded-full text-sm transition-colors ${
            !category
              ? "bg-white text-black"
              : "bg-gray-800 text-gray-300 hover:bg-gray-700"
          }`}
        >
          All
        </Link>
        {categories?.map((cat) => (
          <Link
            key={cat.id}
            href={`/browse?category=${cat.slug}`}
            className={`px-4 py-2 rounded-full text-sm transition-colors ${
              category === cat.slug
                ? "bg-white text-black"
                : "bg-gray-800 text-gray-300 hover:bg-gray-700"
            }`}
          >
            {cat.name}
          </Link>
        ))}
      </div>

      {/* Video grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
        {videos?.map((video) => (
          <VideoCard key={video.id} video={video} />
        ))}
      </div>

      {(!videos || videos.length === 0) && (
        <p className="text-gray-500 text-center py-10">
          No videos found{category ? ` in "${category}"` : ""}.
        </p>
      )}

      {/* Pagination */}
      {totalCount && totalCount > 20 && (
        <div className="flex justify-center gap-4 mt-8">
          {page > 1 && (
            <Link
              href={`/browse?page=${page - 1}${category ? `&category=${category}` : ""}`}
              className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 text-sm"
            >
              Previous
            </Link>
          )}
          <span className="px-4 py-2 text-gray-400 text-sm">
            Page {page} of {Math.ceil(totalCount / 20)}
          </span>
          {page * 20 < totalCount && (
            <Link
              href={`/browse?page=${page + 1}${category ? `&category=${category}` : ""}`}
              className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 text-sm"
            >
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
