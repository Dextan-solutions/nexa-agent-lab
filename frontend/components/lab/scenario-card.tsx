"use client";

import { Bot } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { LabScenario } from "@/lib/lab-v1-api";

function difficultyStyle(d: string) {
  switch (d.toLowerCase()) {
    case "low":
      return "border-red-800/80 bg-red-950/40 text-red-300";
    case "medium":
      return "border-orange-800/80 bg-orange-950/40 text-orange-200";
    case "hard":
      return "border-amber-700/80 bg-amber-950/40 text-amber-200";
    case "chained":
      return "border-fuchsia-800/80 bg-fuchsia-950/40 text-fuchsia-200";
    default:
      return "border-zinc-700 bg-zinc-900 text-zinc-300";
  }
}

export function ScenarioCard({
  scenario,
  inProgress,
  onStart,
}: {
  scenario: LabScenario;
  inProgress: boolean;
  onStart: () => void;
}) {
  const captured = Boolean(scenario.captured);
  const status = captured ? "CAPTURED" : inProgress ? "IN PROGRESS" : "NOT STARTED";
  const statusClass = captured
    ? "text-emerald-400"
    : inProgress
      ? "text-amber-400"
      : "text-zinc-500";

  return (
    <Card
      className={cn(
        "flex flex-col border-zinc-800 bg-zinc-950/80 shadow-md",
        captured && "border-emerald-800/40 bg-emerald-950/20",
      )}
    >
      <CardHeader className="space-y-2 pb-2">
        <div className="flex items-start justify-between gap-2">
          <Badge variant="default" className="border border-zinc-600 font-mono text-[10px] uppercase text-zinc-300">
            <Bot className="mr-1 h-3 w-3" />
            {scenario.agent}
          </Badge>
          <span className={cn("rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase", difficultyStyle(scenario.difficulty))}>
            {scenario.difficulty}
          </span>
        </div>
        <h3 className="line-clamp-2 text-sm font-semibold leading-snug text-zinc-100">{scenario.title}</h3>
      </CardHeader>
      <CardContent className="flex-1 pb-2">
        <p className={cn("font-mono text-[10px] uppercase tracking-wide", statusClass)}>{status}</p>
      </CardContent>
      <CardFooter className="pt-0">
        <Button
          size="sm"
          variant="secondary"
          className={cn(
            "w-full font-mono text-xs",
            captured
              ? "bg-emerald-900/40 text-emerald-400 hover:bg-emerald-900/60"
              : "bg-zinc-800 text-zinc-100 hover:bg-zinc-700",
          )}
          onClick={onStart}
        >
          {captured ? "Review" : "Start"}
        </Button>
      </CardFooter>
    </Card>
  );
}
