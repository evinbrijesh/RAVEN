/**
 * Thin typed fetch client for the RAVEN API (apps/api).
 * Base URL comes from NEXT_PUBLIC_API_URL (default http://localhost:8000).
 */
import type {
  ApiError,
  ApproveHardeningResponse,
  CreateScanResponse,
  FindingsResponse,
  HardeningProposal,
  Report,
  ScanConfig,
  ScanListItem,
  ScanView,
} from "./types";

export const API_BASE_URL: string =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

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

export function listScans(): Promise<ScanListItem[]> {
  return request<ScanListItem[]>("/api/scans");
}

export function createScan(config: ScanConfig): Promise<CreateScanResponse> {
  return request<CreateScanResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export function getScan(scanId: string): Promise<ScanView> {
  return request<ScanView>(`/api/scans/${encodeURIComponent(scanId)}`);
}

export function getFindings(scanId: string): Promise<FindingsResponse> {
  return request<FindingsResponse>(
    `/api/scans/${encodeURIComponent(scanId)}/findings`,
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

export async function getReport(
  scanId: string,
  format: "json" | "markdown" | "sarif",
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
