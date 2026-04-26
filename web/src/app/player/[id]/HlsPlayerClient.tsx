"use client";

import HlsPlayer from "@/components/HlsPlayer";

export default function HlsPlayerClient({ src }: { src: string }) {
  return <HlsPlayer src={src} />;
}
