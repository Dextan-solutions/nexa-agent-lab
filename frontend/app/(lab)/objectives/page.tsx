"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { getLabScenarios, type LabScenario } from "@/lib/lab-v1-api";

function diffBadge(d: string) {
  const x = d.toLowerCase();
  if (x === "low") return <Badge variant="low">Low</Badge>;
  if (x === "medium") return <Badge variant="medium">Medium</Badge>;
  if (x === "hard") return <Badge variant="hard">Hard</Badge>;
  return <Badge variant="chained">Chained</Badge>;
}

export default function ObjectivesPage() {
  const [items, setItems] = React.useState<LabScenario[]>([]);
  const [q, setQ] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await getLabScenarios();
        if (!cancelled) setItems(list);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load scenarios");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = React.useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return items;
    return items.filter((o) =>
      `${o.title} ${o.agent} ${o.workflow} ${o.difficulty} ${o.description} ${o.objective}`.toLowerCase().includes(s)
    );
  }, [items, q]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Objectives</h2>
        <p className="text-sm text-muted-foreground">
          All vulnerability scenarios from <span className="font-mono">GET /api/v1/lab/scenarios</span> — hints, flags,
          and capture state.
        </p>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div>
            <CardTitle>Scenario list</CardTitle>
            <CardDescription>Filter by title, agent, workflow, difficulty, or description.</CardDescription>
          </div>
          <div className="max-w-md">
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search scenarios…" />
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {error ? <div className="text-sm text-destructive">{error}</div> : null}
          {filtered.map((o) => (
            <div key={`${o.agent}:${o.flag}:${o.title}`} className="rounded-lg border bg-background/30 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="text-sm font-semibold">{o.title}</div>
                  <div className="text-xs text-muted-foreground">
                    Agent: <span className="font-mono">{o.agent}</span> • Workflow:{" "}
                    <span className="font-mono">{o.workflow}</span>
                    {o.captured ? (
                      <>
                        {" "}
                        • <span className="text-emerald-600 dark:text-emerald-400">Captured</span>
                      </>
                    ) : null}
                  </div>
                </div>
                <div className="flex items-center gap-2">{diffBadge(o.difficulty)}</div>
              </div>

              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div className="rounded-md border bg-card p-3 md:col-span-2">
                  <div className="text-xs text-muted-foreground">Description</div>
                  <div className="mt-1 text-sm text-muted-foreground">{o.description}</div>
                </div>
                <div className="rounded-md border bg-card p-3">
                  <div className="text-xs text-muted-foreground">Objective</div>
                  <div className="mt-1 text-sm">{o.objective}</div>
                </div>
                <div className="rounded-md border bg-card p-3">
                  <div className="text-xs text-muted-foreground">Flag</div>
                  <div className="mt-1 break-all font-mono text-xs">{o.flag}</div>
                </div>
                <div className="rounded-md border bg-card p-3 md:col-span-2">
                  <div className="text-xs text-muted-foreground">Hints</div>
                  <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                    <li>{o.hint_1}</li>
                    <li>{o.hint_2}</li>
                    <li>{o.hint_3}</li>
                  </ul>
                </div>
              </div>
            </div>
          ))}
          {filtered.length === 0 ? <div className="text-sm text-muted-foreground">No scenarios found.</div> : null}
        </CardContent>
      </Card>
    </div>
  );
}
