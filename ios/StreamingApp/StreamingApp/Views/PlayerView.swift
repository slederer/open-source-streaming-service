import SwiftUI

/// PlayerView wraps the Bitmovin Player iOS SDK.
/// Requires BitmovinPlayer SPM package to be added to the Xcode project:
///   https://github.com/bitmovin/player-ios.git
///
/// For now, this uses AVPlayer as a fallback for development without the SDK.
import AVKit

struct PlayerView: View {
    var videoId: String?
    var liveChannelId: Int?

    @State private var playbackInfo: PlaybackInfo?
    @State private var playerItem: AVPlayerItem?
    @State private var error: String?
    @State private var isLoading = true

    var body: some View {
        VStack {
            if let playerItem = playerItem {
                VideoPlayer(player: AVPlayer(playerItem: playerItem))
                    .ignoresSafeArea()
            } else if isLoading {
                ProgressView("Loading stream...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = error {
                Text(error)
                    .foregroundColor(.red)
                    .padding()
            }
        }
        .background(Color.black)
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await loadPlayback()
        }
    }

    private func loadPlayback() async {
        do {
            let info: PlaybackInfo

            if let videoId = videoId {
                info = try await APIClient.shared.getPlaybackInfo(videoId: videoId)
            } else if let channelId = liveChannelId {
                info = try await APIClient.shared.getLivePlaybackInfo(channelId: channelId)
            } else {
                error = "No video or channel specified"
                isLoading = false
                return
            }

            playbackInfo = info

            // Use session URL (SSAI) if available, else direct manifest
            let urlString = info.sessionUrlHls ?? info.manifestHls
            guard let url = URL(string: urlString), !urlString.isEmpty else {
                error = "No playback URL available"
                isLoading = false
                return
            }

            // NOTE: In production, replace AVPlayer with BitmovinPlayer:
            //   import BitmovinPlayer
            //   let playerConfig = PlayerConfig()
            //   playerConfig.key = "YOUR_PLAYER_KEY"
            //   let sourceConfig = SourceConfig(url: url, type: .hls)
            //   if let drmToken = info.drmToken {
            //       let fairplayConfig = FairPlayConfig(
            //           licenseUrl: URL(string: info.drmFairplayUrl ?? "")!,
            //           certificateUrl: URL(string: info.drmFairplayCertUrl ?? "")!
            //       )
            //       fairplayConfig.prepareLicenseRequestHandler = { request in
            //           request.setValue(drmToken, forHTTPHeaderField: "pallycon-customdata-v2")
            //           return request
            //       }
            //       sourceConfig.drmConfig = fairplayConfig
            //   }

            playerItem = AVPlayerItem(url: url)
            isLoading = false
        } catch {
            self.error = "Failed to load playback info"
            isLoading = false
        }
    }
}
