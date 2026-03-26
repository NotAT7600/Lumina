"use client";

import React, { useEffect } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import { X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Button } from "@/components/ui/button";
import { MermaidDiagram } from "@/components/mermaid-diagram";

interface ReportModalProps {
  open: boolean;
  onClose: () => void;
  report: string | null;
  loading: boolean;
  error: string | null;
  target: string;
  scanId: string;
  onDownload: () => void;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600/15 text-red-400 border border-red-600/30 font-bold",
  high: "bg-orange-500/15 text-orange-400 border border-orange-500/30 font-bold",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30 font-semibold",
  low: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  info: "bg-white/5 text-white/60 border border-white/10",
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

function TdCell({ children }: { children?: React.ReactNode }) {
  const key = String(children).toLowerCase().trim();
  const isSeverity = ["critical", "high", "medium", "low", "info"].includes(key);

  return (
    <td className="px-4 py-2.5 text-sm text-white/75 align-top">
      {isSeverity ? <SeverityBadge>{children}</SeverityBadge> : children}
    </td>
  );
}

const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="text-3xl font-serif font-semibold tracking-tight mb-4 mt-0 text-white">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <div className="mt-10 mb-4">
      <h2 className="text-lg font-semibold pb-2.5 border-b border-white/10 text-white tracking-tight">
        {children}
      </h2>
    </div>
  ),
  h3: ({ children }) => (
    <h3 className="text-base font-semibold mt-8 mb-3 text-white flex items-center gap-2.5">
      <span className="inline-block w-1 h-4 rounded-sm bg-purple-400/60 shrink-0" />
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="text-sm text-white/70 leading-relaxed mb-3">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-white">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-white/70">{children}</em>
  ),
  hr: () => <hr className="border-white/10 my-8" />,
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-purple-400/40 pl-4 italic text-white/65 text-sm my-4">
      {children}
    </blockquote>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-outside ml-4 text-sm text-white/70 space-y-1 mb-3">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-outside ml-4 text-sm text-white/70 space-y-1 mb-3">
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
        <div className="my-5">
          <pre className="rounded-xl bg-[#0d0d0d] border border-white/10 px-5 py-4 overflow-x-auto text-xs font-mono text-[#c9d1d9] leading-relaxed">
            <code className={`${className} font-mono text-[#c9d1d9] text-xs`}>{children}</code>
          </pre>
        </div>
      );
    }

    return (
      <code className="font-mono text-xs bg-white/10 px-1.5 py-0.5 rounded text-white">
        {children}
      </code>
    );
  },
  table: ({ children }) => (
    <div className="overflow-x-auto my-6 rounded-xl border border-white/10">
      <table className="w-full text-sm border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-white/5 text-[11px] uppercase tracking-widest text-white/55">
      {children}
    </thead>
  ),
  tbody: ({ children }) => (
    <tbody className="divide-y divide-white/10">{children}</tbody>
  ),
  tr: ({ children }) => (
    <tr className="hover:bg-white/5 transition-colors">{children}</tr>
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
      className="text-purple-300 underline underline-offset-4 hover:opacity-70 transition-opacity"
    >
      {children}
    </a>
  ),
};

export function ReportModal({
  open,
  onClose,
  report,
  loading,
  error,
  target,
  scanId,
  onDownload,
}: ReportModalProps) {
  const prefersReducedMotion = useReducedMotion();

  function handleBackdropClick(event: React.MouseEvent<HTMLDivElement>) {
    if (event.target === event.currentTarget) {
      onClose();
    }
  }

  useEffect(() => {
    if (!open) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };

    document.addEventListener("keydown", onKeyDown);
    const original = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = original;
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: prefersReducedMotion ? 0 : 0.14, ease: "easeOut" }}
        >
          <motion.div
            className="absolute inset-0 bg-black/72"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: prefersReducedMotion ? 0 : 0.12, ease: "easeOut" }}
          />

          <div
            className="relative h-full w-full flex items-center justify-center p-4 md:p-8"
            onClick={handleBackdropClick}
          >
            <motion.section
              role="dialog"
              aria-modal="true"
              className="w-full max-w-6xl h-[88vh] bg-[#101010] border border-white/10 rounded-2xl shadow-2xl overflow-hidden flex flex-col transform-gpu will-change-transform"
              onClick={(event) => event.stopPropagation()}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: prefersReducedMotion ? 0 : 0.16, ease: [0.22, 1, 0.36, 1] }}
            >
              <header className="h-15 px-5 border-b border-white/10 flex items-center justify-between gap-4 bg-[#151515]">
                <div className="min-w-0">
                  <h2 className="text-sm md:text-base font-semibold text-white">Detailed Vulnerability Report</h2>
                  <p className="text-[11px] text-white/50 font-mono truncate mt-0.5">
                    {target} • #{scanId.slice(0, 8)}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={onDownload} className="border-white/15 bg-white/5 text-white hover:bg-white/10">
                    ↓ Export .md
                  </Button>
                  <button
                    onClick={onClose}
                    aria-label="Close report"
                    className="w-9 h-9 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 text-white/70 hover:text-white transition-colors inline-flex items-center justify-center"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </header>

              <div className="flex-1 overflow-y-auto px-6 md:px-8 py-6">
                {loading && (
                  <div className="h-full flex items-center justify-center">
                    <div className="flex flex-col items-center gap-3">
                      <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
                      <p className="text-sm text-white/50">Loading report…</p>
                    </div>
                  </div>
                )}

                {!loading && error && (
                  <div className="h-full flex items-center justify-center">
                    <p className="text-sm text-red-400 bg-red-400/10 px-4 py-2 rounded-lg border border-red-500/20">{error}</p>
                  </div>
                )}

                {!loading && !error && !report && (
                  <div className="h-full flex items-center justify-center">
                    <p className="text-sm text-white/50">No report generated.</p>
                  </div>
                )}

                {!loading && !error && report && (
                  <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                    {report}
                  </ReactMarkdown>
                )}
              </div>
            </motion.section>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
