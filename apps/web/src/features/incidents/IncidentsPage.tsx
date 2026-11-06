import { useEffect, useState } from "react";
import { api, type Incident, type Page as PageT } from "../../api/client";

const STATUS_FLOW = [
  "OPEN", "TRIAGED", "INVESTIGATING", "CONTAINMENT_IN_PROGRESS",
  "CONTAINED", "RECOVERING", "RESOLVED", "CLOSED",
];

const STATUS_COLORS: Record<string, string> = {
  OPEN: "#dc2626",
  TRIAGED: "#ea580c",
  INVESTIGATING: "#f59e0b",
  CONTAINMENT_IN_PROGRESS: "#3b82f6",
  CONTAINED: "#22c55e",
  RECOVERING: "#22c55e",
  RESOLVED: "#6b7280",
  CLOSED: "#9ca3af",
};

export function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data: PageT<Incident> = await api.listIncidents();
      setIncidents(data.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Security Incidents</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && <p>Loading incidents...</p>}
      {!loading && incidents.length === 0 && !error && (
        <p style={{ color: "#666" }}>No incidents. Correlated alerts will be grouped into incidents here.</p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {incidents.map((inc) => (
          <div key={inc.incident_id} style={{
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderRadius: "4px",
            padding: "1rem",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontWeight: 600 }}>{inc.title ?? "Untitled Incident"}</span>
                <span style={{ marginLeft: "0.5rem", padding: "2px 8px", borderRadius: "3px",
                  background: STATUS_COLORS[inc.status] ?? "#999", color: "#fff", fontSize: "0.75rem" }}>
                  {inc.status}
                </span>
                {inc.severity && (
                  <span style={{ marginLeft: "0.5rem", fontSize: "0.8rem", color: "#666" }}>
                    Severity: {inc.severity}
                  </span>
                )}
              </div>
              <div style={{ fontSize: "0.8rem", color: "#666" }}>
                Created: {new Date(inc.created_at).toLocaleString()}
              </div>
            </div>
            {inc.summary && <p style={{ margin: "0.5rem 0 0", color: "#444", fontSize: "0.9rem" }}>{inc.summary}</p>}

            {/* Status flow indicator */}
            <div style={{ marginTop: "0.5rem", display: "flex", gap: "4px" }}>
              {STATUS_FLOW.map((s) => (
                <div key={s} style={{
                  width: 24, height: 4, borderRadius: 2,
                  background: STATUS_FLOW.indexOf(inc.status) >= STATUS_FLOW.indexOf(s)
                    ? (STATUS_COLORS[inc.status] ?? "#22c55e")
                    : "#e0e0e0",
                }} title={s} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
