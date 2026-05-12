"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ProcessingIndicator } from "@/components/bank/processing-indicator";
import { getStoredAccountNumber, listTransactions, setStoredAccountNumber, transfer } from "@/lib/api";

type Txn = Awaited<ReturnType<typeof listTransactions>>["items"][number];

function formatNgn(amount: number) {
  return `₦ ${Number(amount || 0).toLocaleString("en-NG", { maximumFractionDigits: 2 })}`;
}

export default function TransactionsPage() {
  const [accountNumber, setAccountNumber] = React.useState("0000000001");
  const [q, setQ] = React.useState("");
  const [rows, setRows] = React.useState<Txn[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [toAccount, setToAccount] = React.useState("");
  const [amount, setAmount] = React.useState("");
  const [narration, setNarration] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [transferRef, setTransferRef] = React.useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setStoredAccountNumber(accountNumber);
      const res = await listTransactions(accountNumber, 50);
      setRows(res.items ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load transactions");
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

  const filtered = React.useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rows;
    return rows.filter((t) =>
      `${t.reference_code} ${t.narration} ${t.status} ${t.created_at}`.toLowerCase().includes(s)
    );
  }, [q, rows]);

  async function submitTransfer(e: React.FormEvent) {
    e.preventDefault();
    if (sending) return;
    setSending(true);
    setError(null);
    setTransferRef(null);
    try {
      setStoredAccountNumber(accountNumber);
      const res = await transfer({
        to_account: toAccount,
        amount_ngn: Number(amount || 0),
        narration,
      });
      setTransferRef(res.reference_code);
      setToAccount("");
      setAmount("");
      setNarration("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transfer failed");
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Transactions</h2>
        <p className="text-sm text-muted-foreground">Search and review account activity.</p>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div>
            <CardTitle>Transfer</CardTitle>
            <CardDescription>Send money to any Nigerian bank account (NUBAN).</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <ProcessingIndicator show={sending} />
          <form onSubmit={submitTransfer} className="grid gap-3 md:grid-cols-4">
            <div className="space-y-1 md:col-span-2">
              <div className="text-sm font-medium">To account (NUBAN)</div>
              <Input value={toAccount} onChange={(e) => setToAccount(e.target.value)} inputMode="numeric" placeholder="0123456789" />
            </div>
            <div className="space-y-1">
              <div className="text-sm font-medium">Amount (NGN)</div>
              <Input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="numeric" placeholder="5000" />
            </div>
            <div className="space-y-1 md:col-span-4">
              <div className="text-sm font-medium">Narration</div>
              <Input value={narration} onChange={(e) => setNarration(e.target.value)} placeholder="e.g. Rent April" />
              <div className="text-xs text-muted-foreground">
                Use a clear description for your statement.
              </div>
            </div>
            <div className="md:col-span-4 flex items-center gap-2">
              <Button type="submit" disabled={sending || !toAccount.trim() || !amount.trim() || !narration.trim()}>
                {sending ? "Sending…" : "Send transfer"}
              </Button>
              <Button type="button" variant="outline" onClick={load} disabled={loading || sending}>
                Refresh
              </Button>
              {transferRef ? (
                <div className="text-sm text-muted-foreground">
                  Transfer queued. Reference: <span className="font-mono">{transferRef}</span>
                </div>
              ) : null}
            </div>
          </form>
          {error ? <div className="text-sm text-destructive">{error}</div> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="space-y-3">
          <div>
            <CardTitle>Activity</CardTitle>
            <CardDescription>Reference IDs are used for reconciliations and support.</CardDescription>
          </div>
          <div className="max-w-md">
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by reference, merchant, status…" />
          </div>
        </CardHeader>
        <CardContent>
          <ProcessingIndicator show={loading} />
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full text-left text-sm">
              <thead className="bg-accent/40 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Date</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3">Reference</th>
                  <th className="px-4 py-3">Amount</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((t) => (
                  <tr key={t.reference_code} className="border-t">
                    <td className="px-4 py-3 tabular-nums text-muted-foreground">{String(t.created_at).slice(0, 10)}</td>
                    <td className="px-4 py-3 font-medium">
                      <div className="flex items-center gap-2">
                        <span className="truncate">{t.narration}</span>
                        {Number(t.flagged_by_agent || 0) === 1 ? (
                          <Badge variant="secondary">Under review</Badge>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{t.reference_code}</td>
                    <td className="px-4 py-3 tabular-nums">{formatNgn(Number(t.amount_ngn || 0))}</td>
                    <td className="px-4 py-3">{t.status}</td>
                  </tr>
                ))}
                {filtered.length === 0 ? (
                  <tr>
                    <td className="px-4 py-6 text-sm text-muted-foreground" colSpan={5}>
                      No results.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

