"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ProcessingIndicator } from "@/components/bank/processing-indicator";
import {
  getKycStatus,
  getStoredAccountNumber,
  setStoredAccountNumber,
  uploadKycDocument,
} from "@/lib/api";

const DOC_TYPES = ["Passport", "National ID", "Driver's License", "Utility Bill"] as const;

export default function KycPage() {
  const [customerAccount, setCustomerAccount] = React.useState("0000000001");
  const [kycStatus, setKycStatus] = React.useState<string>("pending");
  const [documentType, setDocumentType] = React.useState<(typeof DOC_TYPES)[number]>("Passport");
  const [file, setFile] = React.useState<File | null>(null);
  const [notes, setNotes] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [loadingStatus, setLoadingStatus] = React.useState(false);
  const [success, setSuccess] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  async function refreshStatus(acct: string) {
    setLoadingStatus(true);
    setError(null);
    try {
      const res = await getKycStatus(acct);
      setKycStatus(res.kyc_status);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load status");
    } finally {
      setLoadingStatus(false);
    }
  }

  React.useEffect(() => {
    const acct = getStoredAccountNumber();
    if (acct) setCustomerAccount(acct);
  }, []);

  React.useEffect(() => {
    if (customerAccount?.trim()) refreshStatus(customerAccount.trim());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit() {
    if (!file || submitting) return;
    setSubmitting(true);
    setSuccess(null);
    setError(null);
    try {
      setStoredAccountNumber(customerAccount);
      await uploadKycDocument({
        customer_account: customerAccount,
        document_type: documentType,
        file,
        additional_notes: notes,
      });
      setSuccess("Document received. Verification typically completes within 24 hours.");
      setFile(null);
      setNotes("");
      await refreshStatus(customerAccount);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">KYC verification</h2>
        <p className="text-sm text-muted-foreground">
          Upload required documents to unlock higher limits and faster processing.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Upload documents</CardTitle>
            <CardDescription>Accepted formats: PDF, PNG, JPG (max 10MB each).</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ProcessingIndicator show={submitting || loadingStatus} />
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
              <div className="text-sm font-medium">Document type</div>
              <select
                className="h-10 w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={documentType}
                onChange={(e) => setDocumentType(e.target.value as (typeof DOC_TYPES)[number])}
              >
                {DOC_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium">Document upload</div>
              <Input
                type="file"
                accept=".pdf,.png,.jpg,.jpeg"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
              <div className="text-xs text-muted-foreground">Upload a clear scan or photo.</div>
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium">Additional notes</div>
              <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes…" />
            </div>

            <div className="flex items-center gap-3">
              <Button onClick={submit} disabled={!file || submitting}>
                {submitting ? "Submitting…" : "Submit for review"}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setFile(null);
                  setNotes("");
                  setSuccess(null);
                  setError(null);
                  setSubmitting(false);
                }}
              >
                Reset
              </Button>
              <Button
                variant="outline"
                onClick={() => refreshStatus(customerAccount)}
                disabled={loadingStatus || submitting}
              >
                Refresh status
              </Button>
            </div>
            {success ? <div className="text-sm text-emerald-600 dark:text-emerald-400">{success}</div> : null}
            {error ? <div className="text-sm text-destructive">{error}</div> : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verification status</CardTitle>
            <CardDescription>Track your verification progress.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-md border bg-background/40 p-3">
              <div className="text-xs text-muted-foreground">Customer</div>
              <div className="mt-1 font-mono text-xs">{customerAccount}</div>
            </div>
            <div className="rounded-md border bg-background/40 p-3">
              <div className="text-xs text-muted-foreground">Status</div>
              <div className="mt-1 text-sm font-medium">{kycStatus}</div>
            </div>
            <div className="rounded-md border bg-background/40 p-3">
              <div className="text-xs text-muted-foreground">Notes</div>
              <div className="mt-1 text-sm text-muted-foreground">
                Ensure uploads are clear and match your profile details.
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

