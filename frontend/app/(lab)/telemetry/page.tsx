"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { getLabTelemetry, type LabTelemetryRow } from "@/lib/lab-v1-api";

export default function TelemetryPage() {
  const [rows, setRows] = React.useState<LabTelemetryRow[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [auto, setAuto] = React.useState(true);

  async function refresh() {
    setError(null);
    try {
      const list = await getLabTelemetry();
      setRows(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load telemetry");
    }
  }

  React.useEffect(() => {
    void refresh();
  }, []);

  React.useEffect(() => {
    if (!auto) return;
    const id = setInterval(() => void refresh(), 1500);
    return () => clearInterval(id);
  }, [auto]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Telemetry</h2>
        <p className="text-sm text-muted-foreground">
          Recent rows from <span className="font-mono">audit_events</span> via{" "}
          <span className="font-mono">GET /api/v1/lab/telemetry</span> (last 50).
        </p>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div>
            <CardTitle>Audit feed</CardTitle>
            <CardDescription>Auto-refresh mirrors the lab console telemetry panel.</CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={() => void refresh()}>
              Refresh
            </Button>
            <Button variant={auto ? "default" : "outline"} onClick={() => setAuto((v) => !v)}>
              {auto ? "Auto: on" : "Auto: off"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {error ? <div className="text-sm text-destructive">{error}</div> : null}
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full min-w-[800px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b bg-muted/40 text-[10px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Agent</th>
                  <th className="px-3 py-2">Workflow</th>
                  <th className="px-3 py-2">Request</th>
                  <th className="px-3 py-2">Level</th>
                  <th className="px-3 py-2">Attack</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Actor</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr
                    key={e.id}
                    className={cn(
                      "border-b",
                      e.attack_detected ? "bg-destructive/10" : "hover:bg-muted/30"
                    )}
                  >
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-muted-foreground">{e.timestamp}</td>
                    <td className="px-3 py-2 font-mono uppercase">{e.agent}</td>
                    <td className="max-w-[160px] truncate px-3 py-2 font-mono text-muted-foreground">{e.workflow}</td>
                    <td className="max-w-[200px] truncate px-3 py-2 font-mono text-[10px] text-muted-foreground">
                      {e.request_id || "—"}
                    </td>
                    <td className="px-3 py-2">{e.security_level}</td>
                    <td className="px-3 py-2">{e.attack_detected ? "1" : "0"}</td>
                    <td className="max-w-[180px] truncate px-3 py-2 text-muted-foreground">{e.attack_type || "—"}</td>
                    <td className="max-w-[120px] truncate px-3 py-2 font-mono text-[10px] text-muted-foreground">
                      {e.actor_id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length === 0 ? <div className="text-sm text-muted-foreground">No audit rows yet.</div> : null}
        </CardContent>
      </Card>
    </div>
  );
}
