import SwiftUI

struct VideoDetailView: View {
    let videoId: String
    @State private var video: Video?
    @State private var isLoading = true

    var body: some View {
        ScrollView {
            if let video = video {
                VStack(alignment: .leading, spacing: 16) {
                    // Poster
                    ZStack {
                        Rectangle()
                            .fill(Color.gray.opacity(0.2))
                            .aspectRatio(16 / 9, contentMode: .fit)
                            .cornerRadius(12)

                        NavigationLink(destination: PlayerView(videoId: video.id)) {
                            Image(systemName: "play.circle.fill")
                                .font(.system(size: 60))
                                .foregroundColor(.white.opacity(0.9))
                        }
                    }

                    // Title
                    Text(video.title)
                        .font(.title)
                        .fontWeight(.bold)

                    // Metadata row
                    HStack(spacing: 12) {
                        Text(String(video.year))
                        Text(video.formattedDuration)
                        Text(video.license)
                            .foregroundColor(.blue)
                        if video.status == "ready" {
                            Text("Ready")
                                .foregroundColor(.green)
                        }
                    }
                    .font(.caption)
                    .foregroundColor(.gray)

                    // Description
                    Text(video.aiDescription.isEmpty ? video.description : video.aiDescription)
                        .foregroundColor(.secondary)

                    // Play button
                    NavigationLink(destination: PlayerView(videoId: video.id)) {
                        HStack {
                            Image(systemName: "play.fill")
                            Text("Play")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.white)
                        .foregroundColor(.black)
                        .cornerRadius(12)
                        .fontWeight(.semibold)
                    }

                    // Attribution
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Label(video.attribution, systemImage: "person.circle")
                        Label(video.license, systemImage: "doc.text")
                    }
                    .font(.caption)
                    .foregroundColor(.gray)
                }
                .padding()
            } else if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity)
                    .padding(.top, 100)
            } else {
                Text("Video not found")
                    .foregroundColor(.gray)
                    .padding(.top, 100)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await loadVideo()
        }
    }

    private func loadVideo() async {
        do {
            video = try await APIClient.shared.getVideo(id: videoId)
        } catch {
            video = nil
        }
        isLoading = false
    }
}
