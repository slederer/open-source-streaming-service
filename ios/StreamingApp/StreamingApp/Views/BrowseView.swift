import SwiftUI

struct BrowseView: View {
    @State private var videos: [Video] = []
    @State private var categories: [Category] = []
    @State private var selectedCategory: String?
    @State private var isLoading = true

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Category pills
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            categoryPill(name: "All", slug: nil)
                            ForEach(categories) { cat in
                                categoryPill(name: cat.name, slug: cat.slug)
                            }
                        }
                        .padding(.horizontal)
                    }

                    // Video grid
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
                    .padding(.horizontal)

                    if isLoading {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                            .padding(.top, 20)
                    }

                    if videos.isEmpty && !isLoading {
                        Text("No videos found")
                            .foregroundColor(.gray)
                            .frame(maxWidth: .infinity)
                            .padding(.top, 40)
                    }
                }
            }
            .navigationTitle("Browse")
            .task {
                await loadContent()
            }
        }
    }

    private func categoryPill(name: String, slug: String?) -> some View {
        Button {
            selectedCategory = slug
            Task { await loadVideos() }
        } label: {
            Text(name)
                .font(.caption)
                .fontWeight(.medium)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(selectedCategory == slug ? Color.white : Color.gray.opacity(0.3))
                .foregroundColor(selectedCategory == slug ? .black : .white)
                .cornerRadius(20)
        }
    }

    private func loadContent() async {
        do {
            categories = try await APIClient.shared.getCategories()
            await loadVideos()
        } catch {
            isLoading = false
        }
    }

    private func loadVideos() async {
        isLoading = true
        do {
            let resp = try await APIClient.shared.getVideos(limit: 50, category: selectedCategory)
            videos = resp.data
        } catch {
            videos = []
        }
        isLoading = false
    }
}
