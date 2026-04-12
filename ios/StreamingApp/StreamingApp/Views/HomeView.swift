import SwiftUI

struct HomeView: View {
    @State private var videos: [Video] = []
    @State private var liveChannels: [LiveChannel] = []
    @State private var isLoading = true
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    // Live banner
                    if !liveChannels.isEmpty {
                        liveBanner
                    }

                    // Featured video
                    if let featured = videos.first {
                        featuredSection(video: featured)
                    }

                    // All videos grid
                    if !videos.isEmpty {
                        videoGrid
                    }

                    if isLoading {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                            .padding(.top, 40)
                    }

                    if let error = error {
                        Text(error)
                            .foregroundColor(.red)
                            .frame(maxWidth: .infinity)
                            .padding(.top, 40)
                    }
                }
                .padding()
            }
            .navigationTitle("OSStream")
            .task {
                await loadContent()
            }
        }
    }

    private var liveBanner: some View {
        ForEach(liveChannels.filter(\.isActive)) { channel in
            NavigationLink(destination: PlayerView(liveChannelId: channel.id)) {
                HStack {
                    Circle()
                        .fill(Color.red)
                        .frame(width: 10, height: 10)
                    Text("LIVE")
                        .font(.caption)
                        .fontWeight(.bold)
                        .foregroundColor(.red)
                    Text(channel.name)
                        .foregroundColor(.white)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .foregroundColor(.gray)
                }
                .padding()
                .background(Color.red.opacity(0.15))
                .cornerRadius(12)
            }
        }
    }

    private func featuredSection(video: Video) -> some View {
        NavigationLink(destination: VideoDetailView(videoId: video.id)) {
            ZStack(alignment: .bottomLeading) {
                Rectangle()
                    .fill(
                        LinearGradient(
                            colors: [.blue.opacity(0.3), .purple.opacity(0.3)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(height: 300)
                    .cornerRadius(16)

                VStack(alignment: .leading, spacing: 8) {
                    Text(video.title)
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundColor(.white)
                    Text(video.description)
                        .font(.subheadline)
                        .foregroundColor(.gray)
                        .lineLimit(2)
                }
                .padding()
            }
        }
    }

    private var videoGrid: some View {
        VStack(alignment: .leading) {
            Text("All Videos")
                .font(.title2)
                .fontWeight(.bold)

            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
            ], spacing: 16) {
                ForEach(videos) { video in
                    NavigationLink(destination: VideoDetailView(videoId: video.id)) {
                        VideoCardView(video: video)
                    }
                }
            }
        }
    }

    private func loadContent() async {
        do {
            async let videosTask = APIClient.shared.getVideos(limit: 50)
            async let liveTask = APIClient.shared.getLiveChannels()

            let (videosResp, live) = try await (videosTask, liveTask)
            videos = videosResp.data
            liveChannels = live
            isLoading = false
        } catch {
            self.error = "Failed to load content"
            isLoading = false
        }
    }
}

struct VideoCardView: View {
    let video: Video

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ZStack(alignment: .bottomTrailing) {
                Rectangle()
                    .fill(Color.gray.opacity(0.3))
                    .aspectRatio(16 / 9, contentMode: .fit)
                    .cornerRadius(8)

                Text(video.formattedDuration)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.black.opacity(0.8))
                    .cornerRadius(4)
                    .padding(6)
            }

            Text(video.title)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundColor(.white)
                .lineLimit(1)

            Text("\(String(video.year)) · \(video.license)")
                .font(.caption2)
                .foregroundColor(.gray)
        }
    }
}
