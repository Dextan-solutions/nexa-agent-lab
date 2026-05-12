"use client";

import { Activity } from "lucide-react";

import { cn } from "@/lib/utils";
import type { LabTelemetryRow } from "@/lib/lab-v1-api";

export function TelemetryDashboard({ events }: { events: LabTelemetryRow[] }) {
  const rows = events.slice(0, 20);

  return (
    <div className="rounded-xl border border-zinc-700/80 bg-zinc-950/80">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3">
        <Activity className="h-4 w-4 text-sky-500" />
        <span className="font-mono text-xs font-semibold uppercase tracking-widest text-zinc-400">Telemetry — audit_events</span>
        <span className="ml-auto font-mono text-[10px] text-zinc-600">last 20 · auto 5s</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[880px] border-collapse text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-zinc-800 text-[10px] uppercase tracking-wider text-zinc-500">
              <th className="px-3 py-2">Time</th>
              <th className="px-3 py-2">Agent</th>
              <th className="px-3 py-2">Workflow</th>
              <th className="px-3 py-2">Request</th>
              <th className="px-3 py-2">Level</th>
              <th className="px-3 py-2">Attack</th>
              <th className="px-3 py-2">Type</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-zinc-500">
                  No audit events yet. Agent activity will appear here.
                </td>
              </tr>
            ) : (
              rows.map((e) => (
                <tr
                  key={e.id}
                  className={cn(
                    "border-b border-zinc-900/80",
                    e.attack_detected ? "bg-red-950/35 text-red-100" : "text-zinc-300 hover:bg-zinc-900/50"
                  )}
                >
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-500">{e.timestamp}</td>
                  <td className="px-3 py-2 uppercase">{e.agent}</td>
                  <td className="max-w-[180px] truncate px-3 py-2 text-zinc-400">{e.workflow}</td>
                  <td className="max-w-[200px] truncate px-3 py-2 text-zinc-500">{e.request_id || "—"}</td>
                  <td className="px-3 py-2">{e.security_level}</td>
                  <td className="px-3 py-2">
                    {e.attack_detected ? (
                      <span className="text-red-400 font-bold">✓</span>
                    ) : (
                      <span className="text-zinc-600">—</span>
                    )}
                  </td>
                  <td className="max-w-[200px] truncate px-3 py-2 text-zinc-500">{e.attack_type || "—"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
