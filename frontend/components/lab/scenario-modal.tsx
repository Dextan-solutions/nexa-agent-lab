"use client";

import * as React from "react";
import { ExternalLink, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { LabScenario, V1SecurityLevel } from "@/lib/lab-v1-api";
import { portalPathForWorkflow, setV1SecurityLevel } from "@/lib/lab-v1-api";
import Link from "next/link";

export function scenarioKey(s: LabScenario) {
  return `${s.agent}-${s.difficulty}-${s.flag}`;
}

function levelForScenario(difficulty: string): V1SecurityLevel {
  const d = difficulty.toLowerCase();
  if (d === "medium") return "medium";
  if (d === "hard") return "hard";
  if (d === "chained") return "low";
  return "low";
}

export function ScenarioModal({
  scenario,
  open,
  onClose,
  onMarkInProgress,
}: {
  scenario: LabScenario | null;
  open: boolean;
  onClose: () => void;
  onMarkInProgress: (s: LabScenario) => void;
}) {
  const [hints, setHints] = React.useState(0);
  const [flagInput, setFlagInput] = React.useState("");
  const [flagOk, setFlagOk] = React.useState<boolean | null>(null);
  const [levelBusy, setLevelBusy] = React.useState(false);

  React.useEffect(() => {
    if (open && scenario) {
      setHints(0);
      setFlagInput("");
      setFlagOk(null);
    }
  }, [open, scenario]);

  if (!open || !scenario) return null;

  const sc = scenario;
  const hintList = [sc.hint_1, sc.hint_2, sc.hint_3].filter(Boolean);

  async function applyRecommendedLevel() {
    setLevelBusy(true);
    try {
      await setV1SecurityLevel(levelForScenario(sc.difficulty));
      onMarkInProgress(sc);
    } catch {
      /* ignore */
    } finally {
      setLevelBusy(false);
    }
  }

  function verifyFlag() {
    const ok = flagInput.trim() === sc.flag.trim();
    setFlagOk(ok);
  }

  const portal = portalPathForWorkflow(sc.workflow);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-zinc-600 bg-zinc-950 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-xs uppercase text-emerald-500/90">{sc.agent}</div>
            <h2 className="mt-1 text-lg font-semibold text-zinc-50">{sc.title}</h2>
          </div>
          <Button type="button" size="icon" variant="ghost" className="text-zinc-400 hover:text-white" onClick={onClose}>
            <X className="h-5 w-5" />
          </Button>
        </div>

        <div className="mt-4 space-y-4 text-sm text-zinc-300">
          <section>
            <div className="font-mono text-xs uppercase tracking-wider text-zinc-500">Objective</div>
            <p className="mt-1 leading-relaxed">{sc.objective}</p>
          </section>

          <section>
            <div className="flex items-center justify-between gap-2">
              <div className="font-mono text-xs uppercase tracking-wider text-zinc-500">Hints</div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="border-zinc-600 font-mono text-xs"
                disabled={hints >= hintList.length}
                onClick={() => setHints((h) => Math.min(h + 1, hintList.length))}
              >
                Reveal next
              </Button>
            </div>
            <ul className="mt-2 space-y-2">
              {hintList.slice(0, hints).map((h, i) => (
                <li key={i} className="rounded border border-zinc-800 bg-zinc-900/80 p-3 font-mono text-xs text-zinc-300">
                  {h}
                </li>
              ))}
              {hints === 0 ? <li className="text-xs italic text-zinc-600">No hints revealed yet.</li> : null}
            </ul>
          </section>

          <section className="flex flex-wrap gap-2">
            <Button type="button" className="bg-emerald-700 font-mono text-xs hover:bg-emerald-600" disabled={levelBusy} onClick={applyRecommendedLevel}>
              {levelBusy ? "…" : `Set level → ${levelForScenario(sc.difficulty).toUpperCase()}`}
            </Button>
            <Button type="button" variant="outline" className="border-zinc-600 font-mono text-xs" asChild>
              <Link href={portal} target="_blank" rel="noreferrer">
                Open portal <ExternalLink className="ml-1 inline h-3 w-3" />
              </Link>
            </Button>
          </section>

          <section>
            <div className="font-mono text-xs uppercase tracking-wider text-zinc-500">Verify flag</div>
            <div className="mt-2 flex gap-2">
              <Input
                value={flagInput}
                onChange={(e) => {
                  setFlagInput(e.target.value);
                  setFlagOk(null);
                }}
                placeholder="AGENTHIVE{...}"
                className="border-zinc-700 bg-zinc-900 font-mono text-sm text-zinc-100"
              />
              <Button type="button" variant="secondary" className="font-mono text-xs" onClick={verifyFlag}>
                Check
              </Button>
            </div>
            {flagOk === true ? <p className="mt-2 font-mono text-sm text-emerald-400">Match — flag verified.</p> : null}
            {flagOk === false ? <p className="mt-2 font-mono text-sm text-red-400">No match.</p> : null}
          </section>
        </div>
      </div>
    </div>
  );
}
