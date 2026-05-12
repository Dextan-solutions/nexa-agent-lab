"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getV1SecurityLevel, setV1SecurityLevel, uiLevelToV1, v1LevelToUi, type SecurityLevelUi } from "@/lib/lab-v1-api";

const levels: SecurityLevelUi[] = ["LOW", "MEDIUM", "HARD", "SECURE"];

export default function SecurityLevelPage() {
  const [current, setCurrent] = React.useState<SecurityLevelUi>("LOW");
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState<SecurityLevelUi | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await getV1SecurityLevel();
        if (!cancelled) setCurrent(v1LevelToUi(s.level));
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function apply(level: SecurityLevelUi) {
    setSaving(level);
    setError(null);
    try {
      const s = await setV1SecurityLevel(uiLevelToV1(level));
      setCurrent(v1LevelToUi(s.level));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Security level</h2>
        <p className="text-sm text-muted-foreground">
          Changes apply immediately (no restart). This intentionally controls vulnerable vs secure behavior.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Current level</CardTitle>
          <CardDescription>Global setting used by all agents and gateway controls.</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Badge variant="default">{loading ? "Loading…" : current}</Badge>
            <span className="text-sm text-muted-foreground">applies across agents + APIs</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {levels.map((lvl) => (
              <Button
                key={lvl}
                variant={lvl === current ? "default" : "outline"}
                onClick={() => apply(lvl)}
                disabled={saving !== null}
              >
                {saving === lvl ? "Applying…" : lvl}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {error ? <div className="text-sm text-destructive">{error}</div> : null}
    </div>
  );
}

