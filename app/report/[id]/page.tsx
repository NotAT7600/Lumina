"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import { Button } from "@/components/ui/button";
import { MermaidDiagram } from "@/components/mermaid-diagram";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Severity badge ────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600/15 text-red-500 border border-red-600/30 font-bold",
  high:     "bg-orange-500/15 text-orange-400 border border-orange-500/30 font-bold",
  medium:   "bg-yellow-500/15 text-yellow-500 border border-yellow-500/30 font-semibold",
  low:      "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  info:     "bg-muted text-muted-foreground border border-border",
};

function SeverityBadge({ children }: { children: React.ReactNode }) {
  const key = String(children).toLowerCase().trim();
  const cls = SEVERITY_STYLES[key];
  if (!cls) return <>{children}</>;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] uppercase tracking-widest ${cls}`}>
      {children}
    </span>
  );
}

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      className="absolute top-2 right-2 text-[10px] font-mono px-2 py-1 rounded bg-white/10 hover:bg-white/20 transition-colors text-muted-foreground hover:text-foreground"
    >
      {copied ? "✓ copied" : "copy"}
    </button>
  );
}

// ── Table cell — auto-badge severities ────────────────────────────────────────

function TdCell({ children }: { children?: React.ReactNode }) {
  const key = String(children).toLowerCase().trim();
  const isSeverity = ["critical", "high", "medium", "low", "info"].includes(key);
  return (
    <td className="px-4 py-2.5 text-sm text-muted-foreground align-top">
      {isSeverity ? <SeverityBadge>{children}</SeverityBadge> : children}
    </td>
  );
}

// ── Markdown component map ────────────────────────────────────────────────────

const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="text-3xl font-serif font-semibold tracking-tight mb-4 mt-0 text-foreground">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <div className="mt-10 mb-4">
      <h2 className="text-lg font-semibold pb-2.5 border-b border-border text-foreground tracking-tight">
        {children}
      </h2>
    </div>
  ),
  h3: ({ children }) => (
    <h3 className="text-base font-semibold mt-8 mb-3 text-foreground flex items-center gap-2.5">
      <span className="inline-block w-1 h-4 rounded-sm bg-primary/40 shrink-0" />
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="text-sm text-muted-foreground leading-relaxed mb-3">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-foreground">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-muted-foreground">{children}</em>
  ),
  hr: () => <hr className="border-border my-8" />,
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-primary/30 pl-4 italic text-muted-foreground text-sm my-4">
      {children}
    </blockquote>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-outside ml-4 text-sm text-muted-foreground space-y-1 mb-3">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-outside ml-4 text-sm text-muted-foreground space-y-1 mb-3">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="leading-relaxed pl-1">{children}</li>,
  pre: ({ children }) => <>{children}</>,
  code: ({ className, children }) => {
    const value = String(children).replace(/\n$/, "");
    const language = (className ?? "").replace("language-", "").toLowerCase();

    if (language === "mermaid") {
      return <MermaidDiagram chart={value} />;
    }

    if (className) {
      return (
        <div className="relative my-5 group">
          <pre className="rounded-xl bg-[#100303] border border-border/40 px-5 py-4 overflow-x-auto text-xs font-mono text-[#c9d1d9] leading-relaxed">
            <code className={`${className} font-mono text-[#c9d1d9] text-xs`}>{children}</code>
          </pre>
          {value && <CopyButton text={value} />}
        </div>
      );
    }

    return (
      <code className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded text-foreground">
        {children}
      </code>
    );
  },
  table: ({ children }) => (
    <div className="overflow-x-auto my-6 rounded-xl border border-border shadow-sm">
      <table className="w-full text-sm border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-muted/50 text-[11px] uppercase tracking-widest text-muted-foreground">
      {children}
    </thead>
  ),
  tbody: ({ children }) => (
    <tbody className="divide-y divide-border/60">{children}</tbody>
  ),
  tr: ({ children }) => (
    <tr className="hover:bg-muted/20 transition-colors">{children}</tr>
  ),
  th: ({ children }) => (
    <th className="text-left px-4 py-3 font-semibold">{children}</th>
  ),
  td: TdCell as Components["td"],
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-primary underline underline-offset-4 hover:opacity-70 transition-opacity"
    >
      {children}
    </a>
  ),
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const [scanDate, setScanDate] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setScanDate(new Date().toLocaleDateString("en-US", {
      year: "numeric", month: "long", day: "numeric",
    }));
  }, []);

  useEffect(() => {
    if (!id) return;
    async function load() {
      try {
        const [reportRes, scanRes] = await Promise.all([
          fetch(`${API}/api/scan/${id}/report`),
          fetch(`${API}/api/scan/${id}`),
        ]);
        const reportData = await reportRes.json();
        const scanData = await scanRes.json();
        setReport(reportData.report || "No report generated.");
        setTarget(scanData.target ?? "");
      } catch {
        setError("Failed to load report");
      }
    }
    load();
  }, [id]);

  function downloadReport() {
    if (!report) return;
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lumina-report-${id?.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (error) {
    return (
      <main className="min-h-screen flex items-center justify-center">
        <p className="text-destructive text-sm">{error}</p>
      </main>
    );
  }

  if (report === null) {
    return (
      <main className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="flex gap-1">
            {[0, 1, 2].map((i) => (
              <span
                key={i}
                className="w-2 h-2 rounded-full bg-muted-foreground/50 animate-bounce"
                style={{ animationDelay: `${i * 0.15}s` }}
              />
            ))}
          </div>
          <p className="text-muted-foreground text-sm">Loading report…</p>
        </div>
      </main>
    );
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#0d0202] text-white">
      <div className="pointer-events-none absolute inset-0 z-0">
        <div className="absolute inset-0 bg-[radial-gradient(760px_420px_at_10%_0%,rgba(220,38,38,0.09),transparent_60%),radial-gradient(680px_360px_at_90%_0%,rgba(185,28,28,0.06),transparent_60%)]" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#0a0a0a]/15 to-[#0a0a0a]/45" />
      </div>

      {/* Sticky top bar */}
      <div className="sticky top-0 z-20 border-b border-white/10 bg-[#100303]/90 backdrop-blur-sm">
        <div className="page-shell">
          <div className="page-container flex h-14 items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-sm font-semibold shrink-0" style={{background:'linear-gradient(120deg,#c4b5fd,#7c3aed)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',backgroundClip:'text'}}>Lumina</span>
              <span className="text-border/60 shrink-0">|</span>
              <span className="text-xs text-muted-foreground font-mono truncate">{target}</span>
            </div>
            <div className="flex gap-2 shrink-0">
              <Button variant="outline" size="sm" onClick={downloadReport}>
                ↓ Export
              </Button>
              <Button variant="outline" size="sm" onClick={() => router.push(`/scan/${id}`)}>
                ← Scan
              </Button>
              <Button variant="outline" size="sm" onClick={() => router.push("/")}>
                New Scan
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="relative z-10 page-shell py-12">
        <div className="page-container">
          {/* Meta banner */}
          <div className="flex flex-wrap gap-x-8 gap-y-2 mb-10 px-5 py-3.5 rounded-xl border border-border bg-muted/30 text-xs font-mono">
            <span className="text-muted-foreground">
              <span className="text-foreground font-semibold mr-1.5">Target</span>{target}
            </span>
            <span className="text-muted-foreground">
              <span className="text-foreground font-semibold mr-1.5">Scan ID</span>{id?.slice(0, 8)}
            </span>
            {scanDate && (
              <span className="text-muted-foreground">
                <span className="text-foreground font-semibold mr-1.5">Date</span>{scanDate}
              </span>
            )}
            <span className="text-muted-foreground">
              <span className="text-foreground font-semibold mr-1.5">Tool</span>Lumina Security v0.1
            </span>
          </div>

          {/* Rendered markdown */}
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
            {report}
          </ReactMarkdown>
        </div>
      </div>
    </main>
  );
}
