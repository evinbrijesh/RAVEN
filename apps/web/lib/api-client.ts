/**
 * Thin typed fetch client for the RAVEN API (apps/api).
 * Base URL comes from NEXT_PUBLIC_API_URL (default http://localhost:8000).
 */
import type {
  ApiError,
  ApproveHardeningResponse,
  ArtifactVerification,
  CreateScanResponse,
  FindingsResponse,
  HardeningProposal,
  Project,
  RegressionCase,
  RegressionsResponse,
  Report,
  ScanConfig,
  ScanListItem,
  ScanView,
} from "./types";

export const API_BASE_URL: string =
  typeof window !== "undefined"
    ? ""
    : (process.env.NEXT_PUBLIC_API_URL ?? process.env.RAVEN_API_URL ?? "http://localhost:8000");

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(
    status: number,
    code: string,
    message: string,
    retryable = false,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

/** Extract the API's error envelope ({error: {code, message, ...}}) or FastAPI detail. */
async function toApiError(response: Response): Promise<ApiRequestError> {
  let code = `HTTP_${response.status}`;
  let message = response.statusText || "Request failed";
  let retryable = false;
  try {
    const body = (await response.json()) as {
      error?: ApiError;
      detail?: ApiError | string;
    };
    if (body.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      retryable = body.error.retryable ?? false;
    } else if (typeof body.detail === "string") {
      message = body.detail;
    } else if (body.detail?.message) {
      code = body.detail.code ?? code;
      message = body.detail.message;
      retryable = body.detail.retryable ?? false;
    }
  } catch {
    // Non-JSON error body; keep defaults.
  }
  return new ApiRequestError(response.status, code, message, retryable);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...init?.headers,
      },
      cache: "no-store",
    });
  } catch (cause) {
    throw new ApiRequestError(
      0,
      "NETWORK_ERROR",
      `Cannot reach RAVEN API at ${API_BASE_URL}. Is it running?`,
      true,
      { cause },
    );
  }
  if (!response.ok) {
    throw await toApiError(response);
  }
  return (await response.json()) as T;
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export function listProjects(): Promise<Project[]> {
  return request<Project[]>("/api/projects");
}

export function createProject(project: {
  project_id: string;
  name: string;
  description?: string;
}): Promise<Project> {
  return request<Project>("/api/projects", {
    method: "POST",
    body: JSON.stringify(project),
  });
}

export function listScans(projectId?: string): Promise<ScanListItem[]> {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return request<ScanListItem[]>(`/api/scans${query}`);
}

export function createScan(config: ScanConfig): Promise<CreateScanResponse> {
  return request<CreateScanResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export function getScan(scanId: string, projectId?: string): Promise<ScanView> {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return request<ScanView>(`/api/scans/${encodeURIComponent(scanId)}${query}`);
}

export function getScanEvents(
  scanId: string,
): Promise<{ items: Array<Record<string, unknown>> }> {
  return request<{ items: Array<Record<string, unknown>> }>(
    `/api/scans/${encodeURIComponent(scanId)}/events/history`,
  );
}

export function getFindings(scanId: string, projectId?: string): Promise<FindingsResponse> {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return request<FindingsResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/findings${query}`,
  );
}

export function getProposal(scanId: string): Promise<HardeningProposal> {
  return request<HardeningProposal>(
    `/api/scans/${encodeURIComponent(scanId)}/proposal`,
  );
}

export function approveHardening(
  scanId: string,
  proposalId: string,
  approved: boolean,
  approvedBy = "demo-user",
): Promise<ApproveHardeningResponse> {
  // Request shape per docs/API_CONTRACT.md §6; Approval is the response type.
  const body = { proposal_id: proposalId, approved, approved_by: approvedBy };
  return request<ApproveHardeningResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/approve-hardening`,
    { method: "POST", body: JSON.stringify(body) },
  );
}

export function promoteFindingToRegression(
  scanId: string,
  findingId: string,
): Promise<{ status: string; regression_id: string; attack_id: string; target_id: string }> {
  return request<{ status: string; regression_id: string; attack_id: string; target_id: string }>(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/promote-regression`,
    { method: "POST" },
  );
}

export function getFindingTranscript(
  scanId: string,
  findingId: string,
): Promise<{
  finding_id: string;
  attack_id: string;
  evidence_refs: Array<{ ref_id: string; kind: string; locator: string; hash_sha256: string }>;
  messages: Array<{ role: string; content: string; tool_name?: string; tool_args_json?: string }>;
}> {
  return request(
    `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/transcript`,
  );
}

export type ReportFormat = "json" | "markdown" | "sarif";

const REPORT_EXTENSIONS: Record<ReportFormat, string> = {
  json: "json",
  markdown: "md",
  sarif: "sarif",
};

/** Fetch a report as parsed data (json/sarif) or text (markdown). */
export async function getReport(
  scanId: string,
  format: ReportFormat,
): Promise<Report | Record<string, unknown> | string> {
  const path = `/api/scans/${encodeURIComponent(scanId)}/report?format=${format}`;
  if (format === "markdown") {
    let response: Response;
    try {
      response = await fetch(`${API_BASE_URL}${path}`, { cache: "no-store" });
    } catch (cause) {
      throw new ApiRequestError(
        0,
        "NETWORK_ERROR",
        `Cannot reach RAVEN API at ${API_BASE_URL}. Is it running?`,
        true,
        { cause },
      );
    }
    if (!response.ok) throw await toApiError(response);
    return (await response.text()) as string;
  }
  return request<Report | Record<string, unknown>>(path);
}

/** Fetch a report artifact as raw text for download (server sets the filename). */
export async function getReportText(
  scanId: string,
  format: ReportFormat,
): Promise<string> {
  const path = `/api/scans/${encodeURIComponent(scanId)}/report?format=${format}&download=true`;
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { cache: "no-store" });
  } catch (cause) {
    throw new ApiRequestError(
      0,
      "NETWORK_ERROR",
      `Cannot reach RAVEN API at ${API_BASE_URL}. Is it running?`,
      true,
      { cause },
    );
  }
  if (!response.ok) throw await toApiError(response);
  return (await response.text()) as string;
}

export function reportFilename(scanId: string, format: ReportFormat): string {
  return `raven-${scanId}-report.${REPORT_EXTENSIONS[format]}`;
}

export function listRegressions(
  targetId = "shophelper-local",
  projectId?: string,
): Promise<RegressionsResponse> {
  let path = `/api/regressions?target_id=${encodeURIComponent(targetId)}`;
  if (projectId) {
    path += `&project_id=${encodeURIComponent(projectId)}`;
  }
  return request<RegressionsResponse>(path);
}

export function verifyArtifact(
  scanId: string,
  artifactId: string,
  projectId?: string,
): Promise<ArtifactVerification> {
  let path = `/api/scans/${encodeURIComponent(scanId)}/artifacts/${encodeURIComponent(artifactId)}/verify`;
  if (projectId) {
    path += `?project_id=${encodeURIComponent(projectId)}`;
  }
  return request<ArtifactVerification>(path);
}

export function toggleRegression(regressionId: string): Promise<{ regression_id: string; active: boolean; status: string }> {
  return request<{ regression_id: string; active: boolean; status: string }>(
    `/api/regressions/${encodeURIComponent(regressionId)}/toggle`,
    { method: "POST" }
  );
}

export function runRegressionSuite(targetId = "shophelper-local"): Promise<{ scan_id: string; status: string; message: string }> {
  return request<{ scan_id: string; status: string; message: string }>("/api/regressions/run", {
    method: "POST",
    body: JSON.stringify({ target_id: targetId }),
  });
}

export interface SystemReadiness {
  ready: boolean;
  status: string;
  database: {
    migrated: boolean;
    url_kind: string;
    error: string | null;
  };
  queue: {
    ready: boolean;
    kind: string;
  };
  fixtures: {
    ready: boolean;
    available: string[];
  };
  model: {
    configured: boolean;
    provider: string;
    name: string;
  };
}

export function getReadiness(): Promise<SystemReadiness> {
  return request<SystemReadiness>("/ready");
}

export function getHealth(): Promise<{ status: string; service: string }> {
  return request<{ status: string; service: string }>("/health");
}

