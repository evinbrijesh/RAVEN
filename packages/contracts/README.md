# contracts

Shared JSON Schema contracts (blueprint §3). These mirror the Pydantic models
in `apps/api/app/domain/` — the Pydantic models are authoritative for runtime
validation; these files are the language-neutral reference for the frontend
and external consumers.

| File | Mirrors |
| --- | --- |
| `scan-create-request.schema.json` | `app.domain.entities.ScanConfig` (API_CONTRACT §2) |
| `scan-view.schema.json` | `app.domain.entities.ScanView` (API_CONTRACT §3) |
| `finding.schema.json` | `app.domain.entities.Finding` (API_CONTRACT §5) |
| `report.schema.json` | `app.domain.report.ReportDocument` (API_CONTRACT §7, ADR 0001) — v1.0 |
| `error.schema.json` | `app.domain.errors.RavenError.to_payload` (API_CONTRACT §9) |

Keep both sides in sync when changing a contract; bump the `$id` version
suffix for breaking changes.
