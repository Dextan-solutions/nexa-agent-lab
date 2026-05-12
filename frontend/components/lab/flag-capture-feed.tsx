"use client";

import { Radio } from "lucide-react";

import type { LabFlagRow } from "@/lib/lab-v1-api";
import { cn } from "@/lib/utils";

export function FlagCaptureFeed({ flags }: { flags: LabFlagRow[] }) {
  return (
    <div className="rounded-xl border border-zinc-700/80 bg-zinc-950/80">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3">
        <Radio className="h-4 w-4 text-emerald-500" />
        <span className="font-mono text-xs font-semibold uppercase tracking-widest text-zinc-400">Flag capture feed</span>
        <span className="ml-auto font-mono text-[10px] text-zinc-600">auto 5s</span>
      </div>
      <div className="max-h-[320px] divide-y divide-zinc-800/80 overflow-y-auto">
        {flags.length === 0 ? (
          <div className="p-6 font-mono text-sm text-zinc-500">No flags in audit trail yet. Run an agent healthcheck or exploit a scenario.</div>
        ) : (
          flags.map((f, i) => (
            <div
              key={`${f.timestamp}-${f.flag}-${i}`}
              className={cn(
                "flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-center sm:justify-between",
                i === 0 && "bg-emerald-950/30",
              )}
            >
              <div className="font-mono text-xs text-zinc-500">{f.timestamp}</div>
              <div className="font-mono text-xs uppercase text-zinc-400">{f.agent}</div>
              <div className="font-mono text-sm text-emerald-400">{f.flag}</div>
              <div className="font-mono text-[10px] text-zinc-500">{f.attack_type || "—"}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
