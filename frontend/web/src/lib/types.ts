export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Role = "member" | "admin" | "owner";

export interface User {
  id: string;
  email: string;
  role: Role;
  org_id: string;
}

export type AnalysisStatus = "queued" | "running" | "done" | "failed";

export interface Upload {
  id: string;
  filename: string;
  byte_size: number;
  line_count: number;
  parsed_count: number;
  created_at: string;
  // The upload's most recent analysis, or null when it has never been analysed.
  analysis_id: string | null;
  analysis_status: AnalysisStatus | null;
  overall_risk: Severity | null;
}

export interface UploadResult {
  id: string;
  filename: string;
  line_count: number;
  parsed_count: number;
  // Ingest launches the analysis; null with analysis_error set if it could not.
  analysis: { id: string; status: AnalysisStatus; scope: string; shards: number } | null;
  analysis_error?: string;
}

export interface Anomaly {
  id: string;
  kind: string;
  severity: Severity;
  confidence: number;
  explanation: string;
  recommendation: string | null;
  entry_ids: number[];
}

export interface TimelineEvent {
  time_range: string;
  headline: string;
  detail: string;
  severity: Severity;
}

export interface Analysis {
  id: string;
  upload_id: string;
  status: AnalysisStatus;
  overall_risk: Severity | null;
  summary: string | null;
  timeline: TimelineEvent[] | null;
  model: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  anomalies: Anomaly[];
}

export interface LogEntryRow {
  id: number;
  line_no: number;
  ts: string | null;
  client_ip: string | null;
  username: string | null;
  host: string | null;
  url: string | null;
  category: string | null;
  action: string | null;
  req_bytes: number | null;
  resp_bytes: number | null;
  threat_name: string | null;
}

export interface EventPage {
  items: LogEntryRow[];
  total: number;
  limit: number;
  offset: number;
  anomalous_entry_ids: number[];
}

export interface TimelineBucket {
  bucket: string;
  total: number;
}

/** --- Phase 6: dashboard, org and security ------------------------------- */

export type AccessLevel = "summary" | "dashboard" | "full";
export type Urgency = "monitor" | "this_week" | "today" | "immediate";

export interface Me {
  id: string;
  email: string;
  role: Role;
  org_id: string;
  org_name?: string;
  org_slug?: string;
  mfa_enabled?: boolean;
  org_require_mfa?: boolean;
}

export interface DashboardSummary {
  requests: number;
  errors: number;
  success_rate: number | null;
  bytes_in: number;
  bytes_out: number;
  cache_hits: number;
  cache_total: number;
  cache_hit_rate: number | null;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  latency_p99_ms: number | null;
  hosts: number;
  uploads: number;
  /** True until ingest writes its first row. Distinguishes "quiet window"
   *  from "nothing has ever been loaded". */
  empty: boolean;
  /** The span the data actually covers, ignoring the selected window. Null
   *  when nothing has been ingested. */
  data_start: string | null;
  data_end: string | null;
}

export interface FindingCount {
  severity: Severity;
  urgency: Urgency;
  count: number;
}

export interface SummaryResponse {
  summary: DashboardSummary;
  findings: FindingCount[];
  scope: "self" | "org";
  from: string;
  to: string;
}

export interface SeriesPoint {
  bucket: string;
  requests: number;
  errors: number;
  bytes_in: number;
  bytes_out: number;
  cache_hits: number;
  cache_total: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  latency_p99_ms: number | null;
}

export interface TopRow {
  label: string;
  requests: number;
  errors: number;
  bytes: number;
}

export interface OrgUser {
  id: string;
  email: string;
  role: Role;
  org_id: string;
}

export interface AccessGrant {
  id: string;
  org_id: string;
  upload_id: string | null;
  subject_user_id: string;
  level: AccessLevel;
  granted_by: string;
  expires_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  actor_user_id: string | null;
  actor_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

export interface StatusBreakdown {
  code: number;
  class: "success" | "redirect" | "client_error" | "server_error";
  reason: string | null;
  requests: number;
  share: number;
  latency_p95_ms: number | null;
}

export interface ActionItem {
  anomaly_id: string;
  filename: string;
  kind: string;
  severity: Severity;
  urgency: Urgency;
  confidence: number;
  explanation: string;
  recommendation: string | null;
  entries: number;
}

export interface ActionPlan {
  items: ActionItem[];
}
