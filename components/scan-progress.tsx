import { ScanState } from "@/types/scan";
import { Brain, Globe, Link2, Database, Zap, Microscope, Package, KeyRound, FileText } from "lucide-react";
import type { LucideIcon } from "lucide-react";

// All possible agent nodes with display metadata.
const AGENT_META: Record<string, { label: string; icon: LucideIcon; tools: string }> = {
  planner:          { label: "Planner",           icon: Brain,       tools: "language detection" },
  recon:            { label: "Recon",             icon: Globe,       tools: "httpx · nmap · whatweb" },
  attack_chain:     { label: "Attack Chain",      icon: Link2,       tools: "LLM reasoning" },
  sqli:             { label: "SQL Injection",     icon: Database,    tools: "sqlmap" },
  sql_injection:    { label: "SQL Injection",     icon: Database,    tools: "sqlmap" },
  xss:              { label: "XSS",              icon: Zap,         tools: "dalfox" },
  static_c:         { label: "C/C++ Analysis",   icon: Microscope,  tools: "cppcheck · semgrep p/c" },
  static:           { label: "Static Analysis",  icon: Microscope,  tools: "semgrep · bandit" },
  static_analysis:  { label: "Static Analysis",  icon: Microscope,  tools: "semgrep · bandit" },
  deps_py:          { label: "Python Deps",      icon: Package,     tools: "pip-audit" },
  deps_js:          { label: "JS Deps",          icon: Package,     tools: "npm audit" },
  deps:             { label: "Dependencies",     icon: Package,     tools: "pip-audit · npm audit" },
  dependencies:     { label: "Dependencies",     icon: Package,     tools: "pip-audit · npm audit" },
  secrets:          { label: "Secrets",          icon: KeyRound,    tools: "trufflehog · detect-secrets" },
  report:           { label: "Report",           icon: FileText,    tools: "LLM synthesis" },
};

interface Props {
  scan: ScanState;
  now?: number; // current Unix timestamp (seconds) — passed from parent to avoid per-component timers
}

function normalizeAgentKey(agentKey: string): string {
  const aliases: Record<string, string> = {
    sql_injection: "sqli",
    static_analysis: "static",
    dependencies: "deps",
    complete: "report",
  };

  return aliases[agentKey] ?? agentKey;
}

function agentStatus(
  agentKey: string,
  scan: ScanState,
): "done" | "running" | "queued" | "skipped" {
  const normalizedAgent = normalizeAgentKey(agentKey);

  // Planner is a synthetic first step and not part of agents_plan.
  // Mark it done as soon as planning output is available.
  if (normalizedAgent === "planner") {
    if (scan.current_agent === "planner") return "running";

    const planningComplete =
      Boolean(scan.architecture_summary?.trim()) ||
      scan.agents_plan.length > 0;

    if (planningComplete) return "done";
    return "queued";
  }

  // Normalise "complete" marker used by backend when fully done.
  const current = normalizeAgentKey(scan.current_agent);

  if (scan.status === "complete") return "done";
  if (current === normalizedAgent) return "running";

  // Determine ordering from the live plan, falling back to render order.
  const planOrder =
    scan.agents_plan.length > 0
      ? scan.agents_plan.map(normalizeAgentKey)
      : [];
  const currentIdx = planOrder.indexOf(current);
  const agentIdx   = planOrder.indexOf(normalizedAgent);

  if (agentIdx !== -1 && currentIdx !== -1 && agentIdx < currentIdx) return "done";
  return "queued";
}

/** Format seconds as "1m 23s" or "45s". */
function fmtSecs(s: number): string {
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function ScanProgress({ scan, now }: Props) {
  const planKeys =
    scan.agents_plan.length > 0
      ? ["planner", ...scan.agents_plan]
      : Object.keys(AGENT_META);

  const visibleAgents = planKeys
    .filter((key) => AGENT_META[key])
    .map((key) => ({ key, ...AGENT_META[key] }));

  // Build a timing label per agent.
  const timingLabel = (key: string, status: "done" | "running" | "queued" | "skipped"): string | null => {
    const startedAt = scan.agent_timings?.[key];
    if (!startedAt) return null;

    if (status === "running" && now) {
      const elapsed = Math.max(0, Math.floor(now - startedAt));
      return `${fmtSecs(elapsed)}`;
    }

    if (status === "done") {
      // Estimate duration: find the next agent in the plan that has a timing.
      const planKeys2 = scan.agents_plan ?? [];
      const idx = planKeys2.indexOf(key);
      let nextStart: number | null = null;
      for (let i = idx + 1; i < planKeys2.length; i++) {
        const t = scan.agent_timings?.[planKeys2[i]];
        if (t) { nextStart = t; break; }
      }
      // Fall back to using now if scan is complete.
      if (!nextStart && scan.status === "complete" && now) nextStart = now;
      if (nextStart) {
        const dur = Math.max(0, Math.floor(nextStart - startedAt));
        return `${fmtSecs(dur)}`;
      }
    }

    return null;
  };

  return (
    <div className="flex flex-col gap-1 w-full">
      {visibleAgents.map((agent) => {
        const status = agentStatus(agent.key, scan);
        const timing = timingLabel(agent.key, status);
        return (
          <div
            key={agent.key}
            className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-muted/40 border border-border/50"
          >
            <div className="flex items-center gap-3">
              <agent.icon className="w-3.5 h-3.5 text-white/35 shrink-0" />
              <div>
                <p className="text-xs font-medium leading-tight text-white/80">{agent.label}</p>
                <p className="text-[10px] text-white/30 font-mono">{agent.tools}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {timing && (
                <span className={`text-[10px] font-mono tabular-nums ${status === "running" ? "text-blue-400/80" : "text-white/25"}`}>
                  {timing}
                </span>
              )}
              <StatusBadge status={status} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function StatusBadge({
  status,
}: {
  status: "done" | "running" | "queued" | "skipped";
}) {
  switch (status) {
    case "done":
      return (
        <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-400/80 bg-emerald-400/10 border border-emerald-400/20 px-2 py-0.5 rounded-full">
          done
        </span>
      );
    case "running":
      return (
        <span className="text-[10px] font-mono uppercase tracking-widest text-blue-300/90 bg-blue-400/10 border border-blue-400/20 px-2 py-0.5 rounded-full flex items-center gap-1.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          active
        </span>
      );
    case "skipped":
      return (
        <span className="text-[10px] font-mono uppercase tracking-widest text-white/20 px-2 py-0.5 rounded-full">
          skip
        </span>
      );
    default:
      return (
        <span className="text-[10px] font-mono uppercase tracking-widest text-white/20 px-2 py-0.5 rounded-full">
          queued
        </span>
      );
  }
}
