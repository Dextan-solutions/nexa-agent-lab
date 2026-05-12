"use client";

import type { LabProgress } from "@/lib/lab-v1-api";

const AGENT_ORDER = ["aria", "vera", "finn", "leo", "max", "ops"];

export function ProgressSummary({ progress }: { progress: LabProgress | null }) {
  if (!progress) {
    return (
      <div className="rounded-xl border border-zinc-700/80 bg-zinc-900/40 p-4 font-mono text-sm text-zinc-500">Loading progress…</div>
    );
  }

  const pct = progress.total_scenarios ? Math.round((100 * progress.captured) / progress.total_scenarios) : 0;

  return (
    <div className="rounded-xl border border-zinc-700/80 bg-zinc-900/60 p-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="text-xs font-semibold uppercase tracking-widest text-zinc-500">Capture progress</div>
          <div className="mt-1 font-mono text-3xl font-bold text-emerald-400">
            {progress.captured}
            <span className="text-zinc-500"> / {progress.total_scenarios}</span>
          </div>
          <div className="mt-2 h-2 w-full max-w-md overflow-hidden rounded-full bg-zinc-800">
            <div className="h-full bg-emerald-500 transition-all" style={{ width: `${pct}%` }} />
          </div>
        </div>
        <div className="text-right font-mono text-xs text-zinc-500">{pct}% complete</div>
      </div>
      <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {AGENT_ORDER.map((ag) => {
          const b = progress.by_agent[ag];
          if (!b) return null;
          return (
            <div key={ag} className="flex items-center justify-between rounded border border-zinc-800 bg-zinc-950/80 px-3 py-2 font-mono text-xs">
              <span className="uppercase text-zinc-400">{ag}</span>
              <span className="text-zinc-200">
                {b.captured}/{b.total}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
