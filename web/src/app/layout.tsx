import type { Metadata } from "next";
import { Geist } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Open Source Streaming",
  description:
    "A demo streaming service showcasing Bitmovin Player, Encoding, Analytics, DRM, and SSAI with open-source content.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${geistSans.variable} antialiased`}>
      <body className="min-h-screen bg-gray-950 text-white">
        <nav className="sticky top-0 z-50 bg-gray-950/90 backdrop-blur border-b border-gray-800">
          <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <Link href="/" className="text-xl font-bold text-white">
              OSS<span className="text-blue-500">tream</span>
            </Link>
            <div className="flex gap-6 text-sm">
              <Link
                href="/"
                className="text-gray-300 hover:text-white transition-colors"
              >
                Home
              </Link>
              <Link
                href="/browse"
                className="text-gray-300 hover:text-white transition-colors"
              >
                Browse
              </Link>
            </div>
          </div>
        </nav>
        <main className="max-w-7xl mx-auto px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
