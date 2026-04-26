"use client";

import { useEffect, useRef } from "react";

interface HlsPlayerProps {
  src: string;
}

export default function HlsPlayer({ src }: HlsPlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !src) return;

    // Safari has native HLS support
    if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = src;
      video.play().catch(() => {});
      return;
    }

    // Chrome/Firefox: use HLS.js
    let hls: import("hls.js").default | null = null;

    import("hls.js").then((HlsModule) => {
      const Hls = HlsModule.default;
      if (Hls.isSupported()) {
        hls = new Hls();
        hls.loadSource(src);
        hls.attachMedia(video);
        hls.on(Hls.Events.MANIFEST_PARSED, () => {
          video.play().catch(() => {});
        });
      }
    });

    return () => {
      if (hls) {
        hls.destroy();
      }
    };
  }, [src]);

  return (
    <video
      ref={videoRef}
      className="w-full h-full"
      controls
      playsInline
    />
  );
}
