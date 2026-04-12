import Foundation

struct Video: Codable, Identifiable {
    let id: String
    let title: String
    let description: String
    let aiDescription: String
    let duration: Int
    let year: Int
    let license: String
    let attribution: String
    let posterUrl: String
    let thumbnailUrls: [String]
    let manifestHls: String
    let manifestDash: String
    let status: String
    let createdAt: String
    var categories: [Category]?

    enum CodingKeys: String, CodingKey {
        case id, title, description, duration, year, license, attribution, status
        case aiDescription = "ai_description"
        case posterUrl = "poster_url"
        case thumbnailUrls = "thumbnail_urls"
        case manifestHls = "manifest_hls"
        case manifestDash = "manifest_dash"
        case createdAt = "created_at"
        case categories
    }

    var formattedDuration: String {
        let h = duration / 3600
        let m = (duration % 3600) / 60
        let s = duration % 60
        if h > 0 {
            return String(format: "%d:%02d:%02d", h, m, s)
        }
        return String(format: "%d:%02d", m, s)
    }
}

struct Category: Codable, Identifiable {
    let id: Int
    let name: String
    let slug: String
}

struct LiveChannel: Codable, Identifiable {
    let id: Int
    let name: String
    let manifestHls: String
    let manifestDash: String
    let isActive: Bool

    enum CodingKeys: String, CodingKey {
        case id, name
        case manifestHls = "manifest_hls"
        case manifestDash = "manifest_dash"
        case isActive = "is_active"
    }
}

struct PaginatedResponse<T: Codable>: Codable {
    let data: [T]
    let page: Int
    let limit: Int
    let totalCount: Int

    enum CodingKeys: String, CodingKey {
        case data, page, limit
        case totalCount = "total_count"
    }
}

struct PlaybackInfo: Codable {
    let manifestHls: String
    let manifestDash: String
    let sessionUrlHls: String?
    let sessionUrlDash: String?
    let drmToken: String?
    let drmWidevineUrl: String?
    let drmFairplayUrl: String?
    let drmFairplayCertUrl: String?

    enum CodingKeys: String, CodingKey {
        case manifestHls = "manifest_hls"
        case manifestDash = "manifest_dash"
        case sessionUrlHls = "session_url_hls"
        case sessionUrlDash = "session_url_dash"
        case drmToken = "drm_token"
        case drmWidevineUrl = "drm_widevine_url"
        case drmFairplayUrl = "drm_fairplay_url"
        case drmFairplayCertUrl = "drm_fairplay_cert_url"
    }
}
