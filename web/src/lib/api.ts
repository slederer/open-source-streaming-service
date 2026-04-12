// On server (SSR), call the backend container directly.
// On client (browser), use relative URLs so nginx proxies to the backend.
const API_BASE =
  typeof window === "undefined"
    ? (process.env.NEXT_PUBLIC_API_URL || "http://backend:8080")
    : "";

export interface Video {
  id: string;
  title: string;
  description: string;
  ai_description: string;
  duration: number;
  year: number;
  license: string;
  attribution: string;
  poster_url: string;
  thumbnail_urls: string[];
  manifest_hls: string;
  manifest_dash: string;
  status: string;
  created_at: string;
  categories?: Category[];
}

export interface Category {
  id: number;
  name: string;
  slug: string;
}

export interface LiveChannel {
  id: number;
  name: string;
  manifest_hls: string;
  manifest_dash: string;
  is_active: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  page: number;
  limit: number;
  total_count: number;
}

export interface PlaybackInfo {
  manifest_hls: string;
  manifest_dash: string;
  session_url_hls?: string;
  session_url_dash?: string;
  drm_token?: string;
  drm_widevine_url?: string;
  drm_fairplay_url?: string;
  drm_fairplay_cert_url?: string;
  stream_id?: string; // Bitmovin Streams ID
}

async function fetchAPI<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    next: { revalidate: 60 },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function getVideos(
  page = 1,
  limit = 20,
  category?: string
): Promise<PaginatedResponse<Video>> {
  const params = new URLSearchParams({
    page: String(page),
    limit: String(limit),
  });
  if (category) params.set("category", category);
  return fetchAPI(`/api/videos?${params}`);
}

export async function getVideo(id: string): Promise<Video> {
  return fetchAPI(`/api/videos/${id}`);
}

export async function getCategories(): Promise<Category[]> {
  return fetchAPI("/api/categories");
}

export async function getLiveChannels(): Promise<LiveChannel[]> {
  return fetchAPI("/api/live/channels");
}

export async function getPlaybackInfo(videoId: string): Promise<PlaybackInfo> {
  return fetchAPI(`/api/videos/${videoId}/playback`);
}

export async function getLivePlaybackInfo(
  channelId: number
): Promise<PlaybackInfo> {
  return fetchAPI(`/api/live/channels/${channelId}/playback`);
}

export function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}
