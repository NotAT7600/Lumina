"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const EXAMPLE_TARGETS = [
  "http://testphp.vulnweb.com",
  "https://github.com/trottomv/python-insecure-app",
];

export function ScanForm() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) {
      toast.error("Enter a URL, GitHub repository, or repo path");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? "Failed to start scan");
      }
      const data = await res.json();
      toast.success("Scan initiated");
      router.push(`/scan/${data.scan_id}`);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ width: "100%" }}>
      {/* Gradient border wrapper */}
      <div
        style={{
          position: "relative",
          borderRadius: "14px",
          padding: "1px",
          background: "linear-gradient(135deg, rgba(255,255,255,0.25), rgba(255,255,255,0.12), rgba(255,255,255,0.06))",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            background: "rgba(8,8,20,0.97)",
            borderRadius: "13px",
            overflow: "hidden",
          }}
        >
          {/* Prefix */}
          <span
            style={{
              padding: "0 10px 0 16px",
              fontFamily: "var(--font-space-mono, monospace)",
              fontSize: "12px",
              color: "rgba(255,255,255,0.35)",
              flexShrink: 0,
              userSelect: "none",
            }}
          >
            /
          </span>

          {/* Input */}
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="url, github.com/owner/repo, or /path/to/repo"
            autoComplete="off"
            spellCheck={false}
            style={{
              flex: 1,
              minWidth: 0,
              background: "transparent",
              border: "none",
              outline: "none",
              padding: "14px 12px 14px 0",
              fontFamily: "var(--font-space-mono, monospace)",
              fontSize: "12px",
              color: "rgba(224,215,255,0.9)",
              letterSpacing: "0.01em",
            }}
          />

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            style={{
              margin: "4px",
              padding: "9px 22px",
              borderRadius: "10px",
              border: "1px solid rgba(255,255,255,0.15)",
              fontFamily: "var(--font-outfit, sans-serif)",
              fontSize: "13px",
              fontWeight: 500,
              letterSpacing: "0.02em",
              color: "white",
              background: loading
                ? "rgba(255,255,255,0.08)"
                : "linear-gradient(135deg, rgba(255,255,255,0.16), rgba(255,255,255,0.07))",
              cursor: loading ? "not-allowed" : "pointer",
              whiteSpace: "nowrap",
              flexShrink: 0,
              transition: "opacity 0.15s",
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? "Scanning..." : "Illuminate"}
          </button>
        </div>
      </div>

      {/* Examples */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          alignItems: "center",
          marginTop: "14px",
          fontFamily: "var(--font-space-mono, monospace)",
          fontSize: "10px",
          color: "rgba(160,150,200,0.3)",
        }}
      >
        <span>examples:</span>
        {EXAMPLE_TARGETS.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTarget(t)}
            style={{
              background: "none",
              border: "none",
              padding: 0,
              fontFamily: "inherit",
              fontSize: "inherit",
              color: "rgba(255,255,255,0.4)",
              cursor: "pointer",
              textDecoration: "underline",
              textUnderlineOffset: "3px",
              textDecorationColor: "rgba(255,255,255,0.15)",
            }}
          >
            {t}
          </button>
        ))}
      </div>
    </form>
  );
}
