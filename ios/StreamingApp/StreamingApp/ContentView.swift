import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            HomeView()
                .tabItem {
                    Label("Home", systemImage: "house")
                }

            BrowseView()
                .tabItem {
                    Label("Browse", systemImage: "square.grid.2x2")
                }
        }
        .preferredColorScheme(.dark)
    }
}
