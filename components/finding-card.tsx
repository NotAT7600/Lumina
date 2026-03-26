"use client";

import { Finding, Severity } from "@/types/scan";

const SEVERITY_STYLES: Record<Severity, { badge: string; border: string; hover: string }> = {
  critical: { badge: "bg-red-600 text-white",          border: "border-red-600/30",    hover: "hover:border-red-500/60" },
  high:     { badge: "bg-orange-500 text-white",       border: "border-orange-500/30", hover: "hover:border-orange-400/60" },
  medium:   { badge: "bg-yellow-500 text-black",       border: "border-yellow-500/30", hover: "hover:border-yellow-400/60" },
  low:      { badge: "bg-blue-500 text-white",         border: "border-blue-500/30",   hover: "hover:border-blue-400/60" },
  info:     { badge: "bg-white/10 text-white/60",      border: "border-white/10",      hover: "hover:border-white/20" },
};

interface Props {
  finding: Finding;
  index: number;
  onClick: (finding: Finding) => void;
}

export function FindingCard({ finding, index, onClick }: Props) {
  const styles = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info;

  return (
    <button
      onClick={() => onClick(finding)}
      className={`w-full text-left rounded-xl border ${styles.border} ${styles.hover} bg-white/2 hover:bg-white/4 transition-all cursor-pointer p-4 flex flex-col gap-2 group`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs font-bold px-2 py-0.5 rounded-full uppercase tracking-wide ${styles.badge}`}>
            {finding.severity}
          </span>
          <span className="text-xs text-white/40 bg-white/5 px-2 py-0.5 rounded-full border border-white/10">
            {finding.tool}
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-xs text-white/25">#{index + 1}</span>
          <span className="text-[10px] text-white/20 group-hover:text-white/40 transition-colors">↗</span>
        </div>
      </div>

      <p className="text-sm font-semibold text-white/90 leading-snug">
        {finding.title}
      </p>

      <p className="text-xs text-white/50 leading-relaxed line-clamp-2">
        {finding.description}
      </p>

      {finding.component && (
        <span className="text-[10px] text-purple-300/60 font-mono">
          {finding.component}
        </span>
      )}
    </button>
  );
}
