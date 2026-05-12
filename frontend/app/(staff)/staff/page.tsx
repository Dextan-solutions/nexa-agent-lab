"use client";

import * as React from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ProcessingIndicator } from "@/components/bank/processing-indicator";
import { submitStaffItRequest } from "@/lib/api";

const REQUEST_TYPES = ["Password reset", "VPN access", "Software install", "System access", "General inquiry"] as const;

export default function StaffHomePage() {
  const [employeeId, setEmployeeId] = React.useState("");
  const [requestType, setRequestType] = React.useState<(typeof REQUEST_TYPES)[number]>("Password reset");
  const [desc, setDesc] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [answer, setAnswer] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!employeeId.trim() || !desc.trim() || submitting) return;
    setSubmitting(true);
    setAnswer(null);
    setError(null);
    try {
      const reqText = `Request type: ${requestType}\n\n${desc}`;
      const res = await submitStaffItRequest({ employee_id: employeeId.trim(), request: reqText });
      setAnswer((res.output?.answer || "").trim() || "Request received. Please check back shortly for updates.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="mx-auto max-w-[1100px] px-6 py-12 space-y-6">
      <div className="rounded-2xl border bg-card p-8 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-sm font-medium text-muted-foreground">Internal</div>
          <span
            className="rounded border border-amber-600/35 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100"
            title="This portal is a security training lab, not a real bank."
          >
            Training environment
          </span>
        </div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">NexaBank Staff Portal</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Submit IT requests for password resets, access provisioning, and workstation support.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>IT request</CardTitle>
            <CardDescription>Provide your employee ID and a clear description.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ProcessingIndicator show={submitting} />
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-2">
                <div className="text-sm font-medium">Employee ID</div>
                <Input value={employeeId} onChange={(e) => setEmployeeId(e.target.value)} placeholder="EMP-1027" />
              </div>
              <div className="space-y-2">
                <div className="text-sm font-medium">Request type</div>
                <select
                  className="h-10 w-full rounded-md border bg-background px-3 py-2 text-sm"
                  value={requestType}
                  onChange={(e) => setRequestType(e.target.value as (typeof REQUEST_TYPES)[number])}
                >
                  {REQUEST_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-2">
                <div className="text-sm font-medium">Description</div>
                <Textarea
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                  placeholder="Describe the issue or access you need…"
                />
              </div>
              <div className="flex items-center gap-2">
                <Button type="submit" disabled={submitting || !employeeId.trim() || !desc.trim()}>
                  {submitting ? "Submitting…" : "Submit request"}
                </Button>
                <Button type="button" variant="outline" onClick={() => setDesc("I can't access VPN after laptop refresh. Please re-provision.")}>
                  Autofill sample
                </Button>
              </div>
              {error ? <div className="text-sm text-destructive">{error}</div> : null}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Response</CardTitle>
            <CardDescription>Guidance from IT support.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {answer ? (
              <div className="rounded-md border bg-background/40 p-3 text-sm whitespace-pre-wrap">{answer}</div>
            ) : (
              <div className="text-sm text-muted-foreground">Submit an IT request to see the response here.</div>
            )}
          </CardContent>
        </Card>
      </div>

      <footer className="border-t pt-4 text-center text-[11px] text-muted-foreground">
        NexaBank is a fictional company for security training purposes only.
      </footer>
    </main>
  );
}

