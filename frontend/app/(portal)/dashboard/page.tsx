"use client";

import * as React from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ProcessingIndicator } from "@/components/bank/processing-indicator";
import {
  getAccount,
  getFinancialSummary,
  getStoredAccountNumber,
  listTransactions,
  setStoredAccountNumber,
} from "@/lib/api";

function formatNgn(amount: number) {
  return `₦ ${Number(amount || 0).toLocaleString("en-NG", { maximumFractionDigits: 2 })}`;
}

export default function DashboardPage() {
  const [accountNumber, setAccountNumber] = React.useState("0000000001");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [acct, setAcct] = React.useState<Awaited<ReturnType<typeof getAccount>> | null>(null);
  const [tx, setTx] = React.useState<Awaited<ReturnType<typeof listTransactions>>["items"]>([]);

  const [question, setQuestion] = React.useState("");
  const [asking, setAsking] = React.useState(false);
  const [advisorAnswer, setAdvisorAnswer] = React.useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setStoredAccountNumber(accountNumber);
      const a = await getAccount(accountNumber);
      const t = await listTransactions(accountNumber, 5);
      setAcct(a);
      setTx(t.items ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    const stored = getStoredAccountNumber();
    if (stored) setAccountNumber(stored);
  }, []);

  React.useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function askAdvisor(e: React.FormEvent) {
    e.preventDefault();
    if (!question.trim() || asking) return;
    setAsking(true);
    setAdvisorAnswer(null);
    setError(null);
    try {
      const res = await getFinancialSummary({ account_id: accountNumber, question });
      const ans = (res.output?.answer || "").trim();
      setAdvisorAnswer(ans || "Thanks — we’ve reviewed your request. Please check your dashboard for updates.");
      setQuestion("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setAsking(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Dashboard</h2>
        <p className="text-sm text-muted-foreground">Overview of balances and recent activity.</p>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div>
            <CardTitle>Account</CardTitle>
            <CardDescription>Use your NUBAN account number to load your profile.</CardDescription>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="max-w-xs">
              <Input
                value={accountNumber}
                onChange={(e) => setAccountNumber(e.target.value)}
                placeholder="0000000001"
                inputMode="numeric"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button onClick={load} disabled={loading}>
                {loading ? "Loading…" : "Load"}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setAcct(null);
                  setTx([]);
                  setStoredAccountNumber(accountNumber);
                }}
                disabled={loading}
              >
                Use this account
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      <ProcessingIndicator show={loading} />
      {error ? <div className="text-sm text-destructive">{error}</div> : null}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Available balance</CardTitle>
            <CardDescription>Primary account</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">{acct ? formatNgn(acct.balance_ngn) : "—"}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              {acct ? `${acct.full_name} • ${acct.account_number}` : "Load an account to view balance"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Pending items</CardTitle>
            <CardDescription>Verification & approvals</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">{acct ? (acct.kyc_status === "verified" ? "0" : "1") : "—"}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              {acct ? `KYC status: ${acct.kyc_status}` : "KYC verification and approvals"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Risk status</CardTitle>
            <CardDescription>Account monitoring</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold">{acct ? (acct.frozen ? "Restricted" : "Normal") : "—"}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              {acct ? (acct.frozen ? "Outgoing transfers are temporarily restricted" : "No active restrictions") : "Account monitoring"}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Financial advisor</CardTitle>
          <CardDescription>Ask about your finances, spending, or budget planning.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <form onSubmit={askAdvisor} className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask about your finances…"
            />
            <Button type="submit" disabled={asking || !question.trim()}>
              {asking ? "Sending…" : "Ask"}
            </Button>
          </form>
          <ProcessingIndicator show={asking} />
          {advisorAnswer ? (
            <div className="rounded-md border bg-background/40 p-3 text-sm whitespace-pre-wrap">{advisorAnswer}</div>
          ) : (
            <div className="text-xs text-muted-foreground">
              Tip: Ask “How much did I spend on transfers in the last 30 days?” or “Suggest ways to reduce fees.”
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent transactions</CardTitle>
          <CardDescription>Last 5 activities</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm">
            {tx.map((t) => (
              <div key={t.reference_code} className="flex items-center justify-between rounded-md border px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate font-medium">{t.narration}</div>
                  <div className="mt-0.5 font-mono text-xs text-muted-foreground">{t.reference_code}</div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="tabular-nums">{formatNgn(Number(t.amount_ngn || 0))}</div>
                  <div className="text-xs text-muted-foreground">{t.status}</div>
                </div>
              </div>
            ))}
            {tx.length === 0 ? (
              <div className="text-sm text-muted-foreground">No recent transactions found.</div>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

