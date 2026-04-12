import Foundation

class APIClient {
    static let shared = APIClient()

    private let baseURL: String

    init(baseURL: String = "http://localhost:8080") {
        self.baseURL = baseURL
    }

    func getVideos(page: Int = 1, limit: Int = 20, category: String? = nil) async throws -> PaginatedResponse<Video> {
        var components = URLComponents(string: "\(baseURL)/api/videos")!
        var queryItems = [
            URLQueryItem(name: "page", value: String(page)),
            URLQueryItem(name: "limit", value: String(limit)),
        ]
        if let category = category {
            queryItems.append(URLQueryItem(name: "category", value: category))
        }
        components.queryItems = queryItems

        let (data, _) = try await URLSession.shared.data(from: components.url!)
        return try JSONDecoder().decode(PaginatedResponse<Video>.self, from: data)
    }

    func getVideo(id: String) async throws -> Video {
        let url = URL(string: "\(baseURL)/api/videos/\(id)")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode(Video.self, from: data)
    }

    func getCategories() async throws -> [Category] {
        let url = URL(string: "\(baseURL)/api/categories")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode([Category].self, from: data)
    }

    func getLiveChannels() async throws -> [LiveChannel] {
        let url = URL(string: "\(baseURL)/api/live/channels")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode([LiveChannel].self, from: data)
    }

    func getPlaybackInfo(videoId: String) async throws -> PlaybackInfo {
        let url = URL(string: "\(baseURL)/api/videos/\(videoId)/playback")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode(PlaybackInfo.self, from: data)
    }

    func getLivePlaybackInfo(channelId: Int) async throws -> PlaybackInfo {
        let url = URL(string: "\(baseURL)/api/live/channels/\(channelId)/playback")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode(PlaybackInfo.self, from: data)
    }
}
