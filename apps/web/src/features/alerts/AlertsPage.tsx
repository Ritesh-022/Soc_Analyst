import { useEffect, useState } from "react";
import { api, type Alert, type Page as PageT } from "../../api/client";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#f59e0b",
  low: "#3b82f6",
};

const STATUS_COLORS: Record<string, string> = {
  NEW: "#dc2626",
  ACKNOWLEDGED: "#f59e0b",
  UNDER_INVESTIGATION: "#3b82f6",
  RESOLVED: "#22c55e",
  FALSE_POSITIVE: "#6b7280",
};

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data: PageT<Alert> = await api.listAlerts();
      setAlerts(data.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const acknowledge = async (id: string) => {
    try {
      await api.acknowledgeAlert(id, "Acknowledged from dashboard");
      load();
    } catch (err) {
      alert((err as Error).message);
    }
  };

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Security Alerts</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && <p>Loading alerts...</p>}
      {!loading && alerts.length === 0 && !error && (
        <p style={{ color: "#666" }}>No alerts. Detection findings will appear here when rules fire.</p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {alerts.map((a) => (
          <div key={a.alert_id} style={{
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderLeft: `4px solid ${SEVERITY_COLORS[a.severity] ?? "#999"}`,
            borderRadius: "4px",
            padding: "1rem",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontWeight: 600 }}>{a.alert_type}</span>
                <span style={{ marginLeft: "0.5rem", padding: "2px 8px", borderRadius: "3px",
                  background: SEVERITY_COLORS[a.severity] ?? "#999", color: "#fff", fontSize: "0.75rem" }}>
                  {a.severity}
                </span>
                <span style={{ marginLeft: "0.5rem", padding: "2px 8px", borderRadius: "3px",
                  background: STATUS_COLORS[a.status] ?? "#999", color: "#fff", fontSize: "0.75rem" }}>
                  {a.status}
                </span>
              </div>
              <div style={{ fontSize: "0.8rem", color: "#666" }}>
                Risk: {a.risk_score}/100 · {new Date(a.observed_at).toLocaleString()}
              </div>
            </div>
            {a.summary && <p style={{ margin: "0.5rem 0 0", color: "#444", fontSize: "0.9rem" }}>{a.summary}</p>}
            {a.status === "NEW" && (
              <button onClick={() => acknowledge(a.alert_id)}
                style={{ marginTop: "0.5rem", padding: "4px 12px", cursor: "pointer", fontSize: "0.8rem" }}>
                Acknowledge
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
