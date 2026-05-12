"use client";

import * as React from "react";
import Link from "next/link";
import { ShieldAlert, Terminal } from "lucide-react";

import { FlagCaptureFeed } from "@/components/lab/flag-capture-feed";
import { ProgressSummary } from "@/components/lab/progress-summary";
import { ScenarioGrid } from "@/components/lab/scenario-grid";
import { ScenarioModal, scenarioKey } from "@/components/lab/scenario-modal";
import { SecurityLevelControl } from "@/components/lab/security-level-control";
import { TelemetryDashboard } from "@/components/lab/telemetry-dashboard";
import type { LabFlagRow, LabProgress, LabScenario, LabTelemetryRow } from "@/lib/lab-v1-api";
import { getLabFlags, getLabProgress, getLabScenarios, getLabTelemetry } from "@/lib/lab-v1-api";

export default function LabConsolePage() {
  const [scenarios, setScenarios] = React.useState<LabScenario[]>([]);
  const [progress, setProgress] = React.useState<LabProgress | null>(null);
  const [flags, setFlags] = React.useState<LabFlagRow[]>([]);
  const [telemetry, setTelemetry] = React.useState<LabTelemetryRow[]>([]);
  const [err, setErr] = React.useState<string | null>(null);
  const [modal, setModal] = React.useState<LabScenario | null>(null);
  const [inProgress, setInProgress] = React.useState<Set<string>>(() => new Set());

  const load = React.useCallback(async () => {
    try {
      const [sc, pr, fl, tv] = await Promise.all([getLabScenarios(), getLabProgress(), getLabFlags(), getLabTelemetry()]);
      setScenarios(sc);
      setProgress(pr);
      setFlags(fl);
      setTelemetry(tv);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load lab data");
    }
  }, []);

  React.useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 5000);
    return () => clearInterval(id);
  }, [load]);

  React.useEffect(() => {
    setInProgress((prev) => {
      const n = new Set(prev);
      for (const s of scenarios) {
        if (s.captured) n.delete(scenarioKey(s));
      }
      return n;
    });
  }, [scenarios]);

  return (
    <div className="min-h-screen bg-[hsl(222_47%_5%)] text-zinc-100">
      <header className="sticky top-0 z-40 border-b border-zinc-800/90 bg-zinc-950/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-700/60 bg-emerald-950/80">
              <Terminal className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <div className="font-mono text-sm font-bold uppercase tracking-widest text-emerald-400/90">NexaBank Agent Lab</div>
              <div className="text-xs text-zinc-500">Pentest training console · live audit + scenarios</div>
            </div>
          </div>
          <nav className="flex flex-wrap items-center gap-3 text-sm">
            <Link href="/dashboard" className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-medium text-zinc-200 hover:border-zinc-500 hover:text-white">
              NexaBank portal
            </Link>
            <Link href="/security-level" className="text-zinc-500 hover:text-zinc-300">
              Legacy lab
            </Link>
            <Link href="/objectives" className="text-zinc-500 hover:text-zinc-300">
              Objectives
            </Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] space-y-8 px-4 py-8">
        {err ? (
          <div className="rounded-lg border border-red-900/60 bg-red-950/40 p-4 font-mono text-sm text-red-300">
            <ShieldAlert className="mb-2 inline h-4 w-4" /> {err}
          </div>
        ) : null}

        <SecurityLevelControl />

        <section className="space-y-3">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Progress</h2>
          <ProgressSummary progress={progress} />
        </section>

        <section className="space-y-3">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Attack scenarios</h2>
          <ScenarioGrid
            scenarios={scenarios}
            inProgressKeys={inProgress}
            onStart={(s) => {
              setModal(s);
              setInProgress((prev) => {
                const n = new Set(prev);
                n.add(scenarioKey(s));
                return n;
              });
            }}
          />
        </section>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-3">
            <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Flags</h2>
            <FlagCaptureFeed flags={flags} />
          </section>
          <section className="space-y-3">
            <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Telemetry</h2>
            <TelemetryDashboard events={telemetry} />
          </section>
        </div>
      </main>

      <ScenarioModal
        scenario={modal}
        open={modal !== null}
        onClose={() => setModal(null)}
        onMarkInProgress={(s) => {
          setInProgress((prev) => {
            const n = new Set(prev);
            n.add(scenarioKey(s));
            return n;
          });
        }}
      />
    </div>
  );
}
