/**
 * API client for the Ascense dashboard.
 * All requests go through /api/v1/ endpoints. The browser must never
 * enforce permissions — the backend checks authorization on every request.
 */

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

// In development, the tenant ID and user ID are passed via headers.
// In production, these come from the authenticated session/JWT.
const TENANT_ID = localStorage.getItem("ascense_tenant_id") ?? "";
const USER_ID = localStorage.getItem("ascense_user_id") ?? "";

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (TENANT_ID) h["X-Tenant-ID"] = TENANT_ID;
  if (USER_ID) h["X-User-ID"] = USER_ID;
  return h;
}

export async function apiGet<T>(path: string): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, { headers: headers() });
  if (!resp.ok) {
    const problem = await resp.json().catch(() => ({}));
    throw new Error(problem.detail ?? `HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    const problem = await resp.json().catch(() => ({}));
    throw new Error(problem.detail ?? `HTTP ${resp.status}`);
  }
  return resp.json();
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EventRecord {
  event_id: string;
  tenant_id: string;
  source_event_id: string;
  gateway_id: string;
  sensor_name: string;
  sensor_instance_id: string;
  event_kind: string;
  observed_at: string;
  ingested_at: string;
  asset_resolution_status: string;
  data: Record<string, unknown>;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface Alert {
  alert_id: string;
  tenant_id: string;
  incident_id: string | null;
  alert_type: string;
  severity: string;
  risk_score: number;
  status: string;
  summary: string;
  observed_at: string;
  created_at: string;
}

export interface Incident {
  incident_id: string;
  tenant_id: string;
  title: string;
  severity: string;
  status: string;
  summary: string;
  created_at: string;
  updated_at: string;
}

export interface Gateway {
  gateway_id: string;
  tenant_id: string;
  name: string;
  status: string;
  last_heartbeat_at: string | null;
  config_version: number;
}

export interface Asset {
  asset_id: string;
  hostname: string;
  asset_type: string;
  criticality: string;
  status: string;
}

export interface SensorStatus {
  name: string;
  instance_id: string;
  status: string;
  last_event_at: string | null;
}

export interface AuditEvent {
  audit_event_id: string;
  action: string;
  actor_id: string;
  actor_type: string;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  occurred_at: string;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export const api = {
  // Generic helpers used by feature pages
  get: <T>(path: string) => apiGet<T>(path),
  post: <T>(path: string, body?: unknown) => apiPost<T>(path, body),

  // Events
  listEvents: (cursor?: string) =>
    apiGet<Page<EventRecord>>(`/api/v1/events?limit=50${cursor ? `&cursor=${cursor}` : ""}`),
  getEvent: (id: string) => apiGet<EventRecord>(`/api/v1/events/${id}`),

  // Alerts
  listAlerts: (cursor?: string, status?: string) =>
    apiGet<Page<Alert>>(`/api/v1/alerts?limit=50${cursor ? `&cursor=${cursor}` : ""}${status ? `&status=${status}` : ""}`),
  getAlert: (id: string) => apiGet<Alert>(`/api/v1/alerts/${id}`),
  acknowledgeAlert: (id: string, reason: string) =>
    apiPost<Alert>(`/api/v1/alerts/${id}/acknowledgements`, { reason }),

  // Incidents
  listIncidents: (cursor?: string) =>
    apiGet<Page<Incident>>(`/api/v1/incidents?limit=50${cursor ? `&cursor=${cursor}` : ""}`),
  getIncident: (id: string) => apiGet<Incident>(`/api/v1/incidents/${id}`),
  transitionIncident: (id: string, target_status: string, reason: string) =>
    apiPost<Incident>(`/api/v1/incidents/${id}/transitions`, { target_status, reason }),

  // Gateways
  listGateways: () => apiGet<Page<Gateway>>(`/api/v1/gateways?limit=50`),
  getGateway: (id: string) => apiGet<Gateway>(`/api/v1/gateways/${id}`),
  getGatewaySensors: (id: string) =>
    apiGet<{ gateway_id: string; sensors: SensorStatus[] }>(`/api/v1/gateways/${id}/sensors`),
  getTelemetryHealth: (id: string) =>
    apiGet<{ gateway_id: string; sensors: SensorStatus[] }>(`/api/v1/gateways/${id}/telemetry-health`),

  // Assets
  listAssets: () => apiGet<Page<Asset>>(`/api/v1/assets?limit=50`),

  // Audit events
  listAuditEvents: (cursor?: string) =>
    apiGet<Page<AuditEvent>>(`/api/v1/audit-events?limit=50${cursor ? `&cursor=${cursor}` : ""}`),

  // Identity
  getCurrentUser: () => apiGet<{ user_id: string; display_name: string; memberships: unknown[] }>(`/api/v1/me`),
};
