const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type V1SecurityLevel = "low" | "medium" | "hard" | "secure";

export type LabScenario = {
  agent: string;
  title: string;
  description: string;
  difficulty: string;
  objective: string;
  hint_1: string;
  hint_2: string;
  hint_3: string;
  flag: string;
  workflow: string;
  captured?: boolean;
};

export type LabFlagRow = {
  timestamp: string;
  agent: string;
  flag: string;
  attack_type: string;
  security_level: string;
};

export type LabTelemetryRow = {
  id: number;
  timestamp: string;
  agent: string;
  workflow: string;
  request_id: string;
  security_level: string;
  attack_detected: boolean;
  attack_type: string;
  actor_id: string;
};

export type LabProgress = {
  total_scenarios: number;
  captured: number;
  by_agent: Record<string, { total: number; captured: number }>;
  by_difficulty: Record<string, { total: number; captured: number }>;
};

/** Uppercase labels for legacy lab UI (security-level page). */
export type SecurityLevelUi = "LOW" | "MEDIUM" | "HARD" | "SECURE";

export function v1LevelToUi(level: string): SecurityLevelUi {
  return level.toUpperCase() as SecurityLevelUi;
}

export function uiLevelToV1(level: SecurityLevelUi): V1SecurityLevel {
  return level.toLowerCase() as V1SecurityLevel;
}

async function v1<T>(path: string, init?: RequestInit): Promise<T> {
  const isWrite = init?.method && init.method !== "GET" && init.method !== "HEAD";
  const res = await fetch(`${API_BASE}/api/v1/lab${path}`, {
    ...init,
    cache: "no-store",
    headers: isWrite
      ? { "content-type": "application/json", ...(init?.headers as Record<string, string> | undefined) }
      : init?.headers,
  });
  if (!res.ok) {
    throw new Error(await res.text());
  }
  return (await res.json()) as T;
}

export async function getV1SecurityLevel(): Promise<{ level: V1SecurityLevel }> {
  return v1("/security-level");
}

export async function setV1SecurityLevel(level: V1SecurityLevel): Promise<{ ok: boolean; level: string }> {
  return v1("/security-level", { method: "POST", body: JSON.stringify({ level }) });
}

export async function getLabScenarios(): Promise<LabScenario[]> {
  return v1("/scenarios");
}

export async function getLabFlags(): Promise<LabFlagRow[]> {
  return v1("/flags");
}

export async function getLabTelemetry(): Promise<LabTelemetryRow[]> {
  return v1("/telemetry");
}

export async function getLabProgress(): Promise<LabProgress> {
  return v1("/progress");
}

export function portalPathForWorkflow(workflow: string): string {
  switch (workflow) {
    case "support_ticket":
      return "/support";
    case "kyc_verification":
      return "/kyc";
    case "statement_generation":
      return "/dashboard";
    case "loan_processing":
      return "/loan-application";
    case "fraud_monitoring":
      return "/transactions";
    case "internal_it":
      return "/staff";
    default:
      return "/dashboard";
  }
}
