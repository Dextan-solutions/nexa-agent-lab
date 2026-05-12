"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ProcessingIndicator } from "@/components/bank/processing-indicator";
import {
  createLoanApplication,
  getStoredAccountNumber,
  setStoredAccountNumber,
} from "@/lib/api";

type Step = 1 | 2 | 3;

const PURPOSES = ["Personal", "Business", "Education", "Medical", "Equipment", "Other"] as const;
const EMPLOYMENT = ["Employed", "Self-employed", "Business owner", "Student", "Other"] as const;

export default function LoanApplicationPage() {
  const [step, setStep] = React.useState<Step>(1);
  const [customerAccount, setCustomerAccount] = React.useState("0000000001");
  const [amount, setAmount] = React.useState("2500000");
  const [monthlyIncome, setMonthlyIncome] = React.useState("420000");
  const [purpose, setPurpose] = React.useState<(typeof PURPOSES)[number]>("Business");
  const [employment, setEmployment] = React.useState<(typeof EMPLOYMENT)[number]>("Employed");
  const [notes, setNotes] = React.useState("");
  const [submitted, setSubmitted] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [reference, setReference] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const acct = getStoredAccountNumber();
    if (acct) setCustomerAccount(acct);
  }, []);

  function next() {
    setStep((s) => (s === 3 ? 3 : ((s + 1) as Step)));
  }
  function back() {
    setStep((s) => (s === 1 ? 1 : ((s - 1) as Step)));
  }

  async function submit() {
    if (submitted || submitting) return;
    setSubmitting(true);
    setError(null);
    setReference(null);
    try {
      setStoredAccountNumber(customerAccount);
      const res = await createLoanApplication({
        amount_requested_ngn: Number(amount || 0),
        purpose,
        monthly_income_ngn: Number(monthlyIncome || 0),
        employment_status: employment,
        additional_notes: notes || null,
      });
      setReference(res.id);
      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Loan application</h2>
        <p className="text-sm text-muted-foreground">
          Complete the application. You’ll receive status updates in your dashboard.
        </p>
      </div>

      <Card>
        <CardHeader className="space-y-2">
          <CardTitle>Application</CardTitle>
          <CardDescription>
            Step {step} of 3 • Please provide accurate information to avoid delays.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <ProcessingIndicator show={submitting} />
          {submitted ? (
            <div className="rounded-md border bg-background/40 p-4">
              <div className="text-sm font-medium">Submitted</div>
              <div className="mt-1 text-sm text-muted-foreground">
                Application submitted. Reference: <span className="font-mono">{reference ?? "—"}</span>. You will be
                notified of the decision within 2 business days.
              </div>
            </div>
          ) : null}
          {error ? <div className="text-sm text-destructive">{error}</div> : null}

          {step === 1 ? (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <div className="text-sm font-medium">Customer account (NUBAN)</div>
                <Input
                  value={customerAccount}
                  onChange={(e) => setCustomerAccount(e.target.value)}
                  placeholder="0000000001"
                  inputMode="numeric"
                />
              </div>
              <div className="space-y-2">
                <div className="text-sm font-medium">Purpose</div>
                <select
                  className="h-10 w-full rounded-md border bg-background px-3 py-2 text-sm"
                  value={purpose}
                  onChange={(e) => setPurpose(e.target.value as (typeof PURPOSES)[number])}
                >
                  {PURPOSES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          ) : null}

          {step === 2 ? (
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2 md:col-span-2">
                <div className="text-sm font-medium">Requested amount (NGN)</div>
                <Input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="numeric" />
              </div>
              <div className="space-y-2">
                <div className="text-sm font-medium">Monthly income (NGN)</div>
                <Input value={monthlyIncome} onChange={(e) => setMonthlyIncome(e.target.value)} inputMode="numeric" />
              </div>
              <div className="space-y-2 md:col-span-3">
                <div className="text-sm font-medium">Employment</div>
                <select
                  className="h-10 w-full rounded-md border bg-background px-3 py-2 text-sm"
                  value={employment}
                  onChange={(e) => setEmployment(e.target.value as (typeof EMPLOYMENT)[number])}
                >
                  {EMPLOYMENT.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          ) : null}

          {step === 3 ? (
            <div className="space-y-2">
              <div className="text-sm font-medium">Additional notes</div>
              <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Any extra context…" />
              <div className="text-xs text-muted-foreground">
                Add context to help the review team. Don’t include OTPs or passwords.
              </div>
            </div>
          ) : null}
        </CardContent>

        <CardFooter className="justify-between">
          <Button variant="outline" onClick={back} disabled={step === 1 || submitted || submitting}>
            Back
          </Button>
          {step < 3 ? (
            <Button onClick={next} disabled={submitted || submitting}>
              Continue
            </Button>
          ) : (
            <Button onClick={submit} disabled={submitted || submitting}>
              {submitting ? "Submitting…" : "Submit application"}
            </Button>
          )}
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Summary</CardTitle>
          <CardDescription>Preview of what will be submitted.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm md:grid-cols-2">
          <div className="rounded-md border bg-background/40 p-3">
            <div className="text-xs text-muted-foreground">Applicant</div>
            <div className="mt-1 font-medium">NexaBank Customer</div>
            <div className="mt-1 font-mono text-xs text-muted-foreground">{customerAccount}</div>
          </div>
          <div className="rounded-md border bg-background/40 p-3">
            <div className="text-xs text-muted-foreground">Request</div>
            <div className="mt-1 font-medium">₦ {Number(amount || 0).toLocaleString()}</div>
            <div className="mt-1 text-xs text-muted-foreground">Monthly income: ₦ {Number(monthlyIncome || 0).toLocaleString()}</div>
          </div>
          <div className="rounded-md border bg-background/40 p-3 md:col-span-2">
            <div className="text-xs text-muted-foreground">Purpose</div>
            <div className="mt-1">{purpose}</div>
          </div>
          <div className="rounded-md border bg-background/40 p-3 md:col-span-2">
            <div className="text-xs text-muted-foreground">Additional notes</div>
            <div className="mt-1 whitespace-pre-wrap text-sm text-muted-foreground">{notes || "—"}</div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

