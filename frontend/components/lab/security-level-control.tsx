"use client";

import * as React from "react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { getV1SecurityLevel, setV1SecurityLevel, type V1SecurityLevel } from "@/lib/lab-v1-api";

const LEVELS: V1SecurityLevel[] = ["low", "medium", "hard", "secure"];

const styles: Record<V1SecurityLevel, { label: string; badge: string; ring: string }> = {
  low: { label: "LOW", badge: "bg-red-600/90 text-white border-red-500", ring: "ring-red-500/40" },
  medium: { label: "MEDIUM", badge: "bg-orange-500/90 text-black border-orange-400", ring: "ring-orange-400/40" },
  hard: { label: "HARD", badge: "bg-amber-400/90 text-black border-amber-300", ring: "ring-amber-300/40" },
  secure: { label: "SECURE", badge: "bg-emerald-600/90 text-white border-emerald-500", ring: "ring-emerald-500/40" },
};

export function SecurityLevelControl() {
  const [level, setLevel] = React.useState<V1SecurityLevel>("low");
  const [loading, setLoading] = React.useState(true);
  const [pending, setPending] = React.useState<V1SecurityLevel | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      const r = await getV1SecurityLevel();
      setLevel(r.level);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load level");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  async function apply(l: V1SecurityLevel) {
    setPending(l);
    setError(null);
    try {
      const r = await setV1SecurityLevel(l);
      setLevel(r.level as V1SecurityLevel);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to set level");
    } finally {
      setPending(null);
    }
  }

  const cur = styles[level];

  return (
    <div className="rounded-xl border border-zinc-700/80 bg-zinc-900/60 p-6 shadow-lg backdrop-blur">
      <div className="text-xs font-semibold uppercase tracking-widest text-zinc-500">Global security level</div>
      <div className="mt-4 flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div
          className={cn(
            "inline-flex items-center gap-3 rounded-lg border px-5 py-4 font-mono text-2xl font-bold tracking-tight ring-2",
            cur.badge,
            cur.ring
          )}
        >
          {loading ? "…" : cur.label}
        </div>
        <div className="flex flex-wrap gap-2">
          {LEVELS.map((l) => {
            const s = styles[l];
            const active = l === level;
            return (
              <Button
                key={l}
                size="lg"
                variant="outline"
                disabled={pending !== null}
                className={cn(
                  "border-zinc-600 bg-zinc-950/80 font-mono text-xs uppercase text-zinc-200 hover:bg-zinc-800",
                  active && "border-zinc-300 bg-zinc-800 text-white"
                )}
                onClick={() => apply(l)}
              >
                {pending === l ? "…" : s.label}
              </Button>
            );
          })}
        </div>
      </div>
      {error ? <p className="mt-3 font-mono text-sm text-red-400">{error}</p> : null}
      <p className="mt-3 text-xs text-zinc-500">
        Applied to the running backend immediately. Red = intentionally vulnerable; green = hardened controls.
      </p>
    </div>
  );
}
