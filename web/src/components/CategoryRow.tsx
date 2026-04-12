import { Video } from "@/lib/api";
import VideoCard from "./VideoCard";

interface CategoryRowProps {
  title: string;
  videos: Video[];
}

export default function CategoryRow({ title, videos }: CategoryRowProps) {
  if (videos.length === 0) return null;

  return (
    <section className="mb-8">
      <h2 className="text-xl font-bold text-white mb-4">{title}</h2>
      <div className="flex gap-4 overflow-x-auto pb-4 scrollbar-hide">
        {videos.map((video) => (
          <div key={video.id} className="flex-shrink-0 w-64">
            <VideoCard video={video} />
          </div>
        ))}
      </div>
    </section>
  );
}
