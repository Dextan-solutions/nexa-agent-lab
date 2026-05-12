"use client";

import * as React from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getLabTelemetry } from "@/lib/lab-v1-api";

export default function ReplayPage() {
  const [requestIds, setRequestIds] = React.useState<string[]>([]);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      const rows = await getLabTelemetry();
      const ids = new Set<string>();
      for (const e of rows) {
        const rid = e.request_id?.trim();
        if (rid && rid !== "-") ids.add(rid);
      }
      const list = Array.from(ids).slice(-40).reverse();
      if (!cancelled) setRequestIds(list);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Replay</h2>
        <p className="text-sm text-muted-foreground">
          Recent <span className="font-mono">request_id</span> values from audit telemetry (last 50 events). Full replay
          reconstruction can be added later.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent request IDs</CardTitle>
          <CardDescription>Use these IDs to correlate audit entries across agents.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {requestIds.length ? (
            requestIds.map((id) => (
              <div key={id} className="rounded-md border bg-background/30 px-3 py-2 font-mono text-xs text-muted-foreground">
                {id}
              </div>
            ))
          ) : (
            <div className="text-sm text-muted-foreground">No request IDs in recent audit rows.</div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
