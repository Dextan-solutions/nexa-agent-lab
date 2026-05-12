const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type NexaError = {
  error: {
    code: string;
    message: string;
    reference: string;
    support?: string;
  };
};

export type AuthLoginRequest = {
  account_number: string;
  pin: string;
};

export type AuthLoginResponse = {
  ok: boolean;
  access_token: string;
  token_type: "bearer";
};

export type AccountRecord = {
  id: string;
  account_number: string;
  full_name: string;
  email: string;
  phone: string;
  bvn?: string;
  account_type?: string;
  balance_ngn: number;
  tier: number;
  kyc_status: string;
  frozen: number;
  created_at?: string;
  last_login_at?: string | null;
};

export type TransactionRecord = {
  reference_code: string;
  amount_ngn: number;
  type: string;
  channel: string;
  narration: string;
  status: string;
  created_at: string;
  flagged_by_agent?: number;
  sender_account?: string;
  receiver_account?: string;
  internal_flags?: unknown;
};

export type SupportTicketCreateRequest = {
  customer_account: string;
  subject: string;
  body: string;
  channel: "web";
};

export type SupportTicketCreateResponse = {
  ok: boolean;
  ticket_number: string;
  id: string;
};

export type LoanApplicationCreateRequest = {
  amount_requested_ngn: number;
  purpose: string;
  monthly_income_ngn: number;
  employment_status: string;
  additional_notes?: string | null;
};

export type LoanApplicationCreateResponse = {
  ok: boolean;
  id: string;
  application_status: string;
};

export type KycStatusResponse = {
  ok: boolean;
  customer_account: string;
  kyc_status: string;
  tier: number;
};

export type KycUploadResponse = {
  ok: boolean;
  document_id: string;
  status: string;
};

export type FinancialSummaryRequest = {
  account_id: string;
  question?: string | null;
};

export type FinancialSummaryResponse = {
  ok: boolean;
  output: {
    account_id: string;
    customer_notice?: { headline?: string; detail?: string };
    report?: string;
    answer?: string;
  };
};

export type TransferRequest = {
  to_account: string;
  amount_ngn: number;
  narration: string;
};

export type TransferResponse = {
  ok: boolean;
  reference_code: string;
  status: string;
};

export type StaffItRequest = {
  employee_id: string;
  request: string;
};

export type StaffItResponse = {
  ok: boolean;
  output: {
    employee_id: string;
    staff_notice?: { headline?: string; detail?: string };
    answer?: string;
  };
};

const LS_TOKEN = "nexabank_jwt";
const LS_ACCOUNT = "nexabank_account_number";

export function getStoredAccountNumber(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(LS_ACCOUNT);
}

export function setStoredAccountNumber(acct: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(LS_ACCOUNT, acct);
}

export function getStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(LS_TOKEN);
}

export function setStoredToken(token: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(LS_TOKEN, token);
}

export function clearStoredSession() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(LS_TOKEN);
  window.localStorage.removeItem(LS_ACCOUNT);
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return (await res.json()) as T;
}

export async function authLogin(body: AuthLoginRequest): Promise<AuthLoginResponse> {
  const res = await requestJson<AuthLoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (res?.access_token) {
    setStoredToken(res.access_token);
    setStoredAccountNumber(body.account_number);
  }
  return res;
}

export async function getAccount(accountId: string): Promise<AccountRecord> {
  return await requestJson<AccountRecord>(`/api/v1/accounts/${encodeURIComponent(accountId)}`, { method: "GET" });
}

export async function listTransactions(accountId: string, limit = 50): Promise<{ items: TransactionRecord[] }> {
  return await requestJson<{ items: TransactionRecord[] }>(
    `/api/v1/accounts/${encodeURIComponent(accountId)}/transactions?limit=${encodeURIComponent(String(limit))}`,
    { method: "GET" }
  );
}

export async function createSupportTicket(body: SupportTicketCreateRequest): Promise<SupportTicketCreateResponse> {
  return await requestJson<SupportTicketCreateResponse>("/api/v1/support/tickets", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function createLoanApplication(
  body: LoanApplicationCreateRequest
): Promise<LoanApplicationCreateResponse> {
  return await requestJson<LoanApplicationCreateResponse>("/api/v1/loans/applications", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function getKycStatus(customerAccount: string): Promise<KycStatusResponse> {
  return await requestJson<KycStatusResponse>(`/api/v1/kyc/status?customer_account=${encodeURIComponent(customerAccount)}`, {
    method: "GET",
  });
}

export async function uploadKycDocument(args: {
  customer_account: string;
  document_type: string;
  file: File;
  additional_notes?: string;
}): Promise<KycUploadResponse> {
  const token = getStoredToken();
  const form = new FormData();
  form.set("customer_account", args.customer_account);
  form.set("document_type", args.document_type);
  form.set("file", args.file);
  if (args.additional_notes != null) form.set("additional_notes", args.additional_notes);

  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);

  const res = await fetch(`${API_BASE}/api/v1/kyc/documents`, { method: "POST", body: form, headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return (await res.json()) as KycUploadResponse;
}

export async function getFinancialSummary(body: FinancialSummaryRequest): Promise<FinancialSummaryResponse> {
  return await requestJson<FinancialSummaryResponse>("/api/v1/financial/summary", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function transfer(body: TransferRequest): Promise<TransferResponse> {
  return await requestJson<TransferResponse>("/api/v1/transactions/transfer", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function submitStaffItRequest(body: StaffItRequest): Promise<StaffItResponse> {
  return await requestJson<StaffItResponse>("/api/v1/staff/it-request", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

