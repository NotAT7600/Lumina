"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Finding } from "@/types/scan";

const SEVERITY_STYLES: Record<string, { badge: string; glow: string }> = {
  critical: { badge: "bg-red-600 text-white",        glow: "border-red-600/30" },
  high:     { badge: "bg-orange-500 text-white",     glow: "border-orange-500/30" },
  medium:   { badge: "bg-yellow-500 text-black",     glow: "border-yellow-500/30" },
  low:      { badge: "bg-blue-500 text-white",       glow: "border-blue-500/30" },
  info:     { badge: "bg-white/10 text-white/60",    glow: "border-white/10" },
};

interface Props {
  finding: Finding | null;
  onClose: () => void;
}

export function EvidenceDrawer({ finding, onClose }: Props) {
  const prefersReducedMotion = useReducedMotion();

  useEffect(() => {
    if (!finding) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    const orig = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = orig;
    };
  }, [finding, onClose]);

  const styles = finding ? (SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info) : SEVERITY_STYLES.info;

  return (
    <AnimatePresence>
      {finding && (
        <motion.div
          className="fixed inset-0 z-50 flex justify-end"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: prefersReducedMotion ? 0 : 0.15 }}
        >
          {/* Backdrop */}
          <motion.div
            className="absolute inset-0 bg-black/60"
            onClick={onClose}
          />

          {/* Drawer */}
          <motion.aside
            className={`relative w-full max-w-xl h-full bg-[#101010] border-l ${styles.glow} border flex flex-col shadow-2xl`}
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ duration: prefersReducedMotion ? 0 : 0.22, ease: [0.22, 1, 0.36, 1] }}
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-4 px-6 py-5 border-b border-white/10 bg-[#151515]">
              <div className="flex flex-col gap-1.5 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-full uppercase tracking-wide ${styles.badge}`}>
                    {finding.severity}
                  </span>
                  <span className="text-xs text-white/40 bg-white/5 px-2 py-0.5 rounded-full border border-white/10">
                    {finding.tool}
                  </span>
                  {finding.component && (
                    <span className="text-xs text-purple-300/70 bg-purple-400/5 px-2 py-0.5 rounded-full border border-purple-400/15">
                      {finding.component}
                    </span>
                  )}
                </div>
                <h2 className="text-base font-semibold text-white leading-snug">
                  {finding.title}
                </h2>
              </div>
              <button
                onClick={onClose}
                aria-label="Close drawer"
                className="mt-0.5 w-8 h-8 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 text-white/60 hover:text-white transition-colors inline-flex items-center justify-center shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-6">
              {/* Description */}
              <section>
                <h3 className="text-[10px] font-semibold uppercase tracking-widest text-white/35 mb-2">
                  Description
                </h3>
                <p className="text-sm text-white/70 leading-relaxed">
                  {finding.description}
                </p>
              </section>

              {/* Evidence */}
              {finding.evidence && (
                <section>
                  <h3 className="text-[10px] font-semibold uppercase tracking-widest text-white/35 mb-2">
                    Evidence
                  </h3>
                  <pre className="text-xs font-mono bg-[#0d0d0d] border border-white/10 rounded-xl p-4 overflow-x-auto whitespace-pre-wrap break-all text-[#c9d1d9] leading-relaxed max-h-80 overflow-y-auto">
                    {finding.evidence}
                  </pre>
                </section>
              )}

              {/* Remediation */}
              {finding.remediation && (
                <section>
                  <h3 className="text-[10px] font-semibold uppercase tracking-widest text-white/35 mb-2">
                    Remediation
                  </h3>
                  <p className="text-sm text-white/70 leading-relaxed">
                    {finding.remediation}
                  </p>
                </section>
              )}

              {/* Agent metadata */}
              <section className="pt-2 border-t border-white/5">
                <h3 className="text-[10px] font-semibold uppercase tracking-widest text-white/35 mb-2">
                  Detection
                </h3>
                <div className="flex gap-4 text-xs text-white/50 font-mono">
                  <span>Agent: <span className="text-white/70">{finding.agent}</span></span>
                  <span>Tool: <span className="text-white/70">{finding.tool}</span></span>
                </div>
              </section>
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
