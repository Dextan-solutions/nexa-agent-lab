"use client";

import * as React from "react";

import type { LabScenario } from "@/lib/lab-v1-api";
import { ScenarioCard } from "./scenario-card";
import { scenarioKey } from "./scenario-modal";

function sortKey(s: LabScenario) {
  const order = ["aria", "vera", "finn", "leo", "max", "ops"];
  const di = ["low", "medium", "hard", "chained"].indexOf(s.difficulty.toLowerCase());
  return `${order.indexOf(s.agent)}-${di}-${s.title}`;
}

export function ScenarioGrid({
  scenarios,
  inProgressKeys,
  onStart,
}: {
  scenarios: LabScenario[];
  inProgressKeys: Set<string>;
  onStart: (s: LabScenario) => void;
}) {
  const sorted = React.useMemo(() => [...scenarios].sort((a, b) => sortKey(a).localeCompare(sortKey(b))), [scenarios]);

  if (sorted.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-8 text-center">
        <p className="font-mono text-sm text-zinc-500">Loading scenarios...</p>
      </div>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
      {sorted.map((s) => {
        const key = scenarioKey(s);
        return <ScenarioCard key={key} scenario={s} inProgress={inProgressKeys.has(key)} onStart={() => onStart(s)} />;
      })}
    </div>
  );
}
