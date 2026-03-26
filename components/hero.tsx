"use client";

import dynamic from "next/dynamic";
import { ScanForm } from "./scan-form";
import { useState } from "react";
import { Lock } from "lucide-react";

const GL = dynamic(() => import("./gl").then((m) => ({ default: m.GL })), {
  ssr: false,
  loading: () => null,
});

export function Hero() {
  const [hovering, setHovering] = useState(false);

  return (
    <div
      style={{
        position: "relative",
        minHeight: "100svh",
        display: "flex",
        flexDirection: "column",
        background: "#080810",
      }}
    >
      {/* Particle canvas - fills viewport behind everything */}
      <GL hovering={hovering} />

      {/* Branding + form pinned to bottom center */}
      <div
        style={{
          position: "relative",
          zIndex: 10,
          marginTop: "auto",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
          padding: "0 1.5rem 64px",
        }}
      >
        {/* Wordmark */}
        <h1
          style={{
            fontFamily: "var(--font-outfit, sans-serif)",
            fontSize: "clamp(56px, 10vw, 112px)",
            fontWeight: 300,
            letterSpacing: "-0.04em",
            lineHeight: 1,
            marginBottom: "12px",
            textShadow: "0 0 40px rgba(0,0,0,0.8), 0 2px 20px rgba(0,0,0,0.6)",
            background: "linear-gradient(160deg, #ffffff 0%, #e2e8f0 50%, #94a3b8 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
            color: "transparent",
          }}
        >
          Lumina
        </h1>

        {/* Tagline */}
        <p
          style={{
            fontFamily: "var(--font-space-mono, monospace)",
            fontSize: "11px",
            color: "rgba(255,255,255,0.6)",
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            marginBottom: "8px",
            textShadow: "0 1px 12px rgba(0,0,0,0.9)",
          }}
        >
          Autonomous security intelligence
        </p>

        {/* Divider accent */}
        <div
          style={{
            width: "40px",
            height: "1px",
            background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)",
            margin: "0 auto 32px",
          }}
        />

        {/* Form */}
        <div
          style={{ width: "100%", maxWidth: "520px" }}
          onMouseEnter={() => setHovering(true)}
          onMouseLeave={() => setHovering(false)}
        >
          <ScanForm />
        </div>

        {/* Disclaimer */}
        <p
          style={{
            marginTop: "16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
            fontFamily: "var(--font-space-mono, monospace)",
            fontSize: "10px",
            color: "rgba(255,255,255,0.3)",
            letterSpacing: "0.03em",
            textShadow: "0 1px 8px rgba(0,0,0,0.8)",
          }}
        >
          <Lock size={10} />
          Web scans use allowlisted hosts - GitHub repos use isolated backend storage.
        </p>
      </div>
    </div>
  );
}
