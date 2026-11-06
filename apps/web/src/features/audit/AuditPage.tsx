import { useEffect, useState } from "react";
import { api, type AuditEvent, type Page as PageT } from "../../api/client";

const OUTCOME_COLORS: Record<string, string> = {
  success: "#22c55e",
  failure: "#dc2626",
};

const ACTION_ICONS: Record<string, string> = {
  "gateway.enrollment_token_created": "🔑",
  "alert.acknowledged": "✅",
  "incident.transitioned": "🔄",
  "proposal.created": "📋",
  "approval.recorded": "🛡️",
  "event.ingested": "📡",
  "command.claimed": "⚡",
};

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async (cursor?: string) => {
    setLoading(true);
    try {
      const data: PageT<AuditEvent> = await api.listAuditEvents(cursor);
      setEvents((prev) => (cursor ? [...prev, ...data.items] : data.items));
      setNextCursor(data.next_cursor);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Audit Log</h2>
      <p style={{ color: "#666", fontSize: "0.85rem", marginBottom: "1rem" }}>
        Append-only record of all security-relevant operations. Records are never deleted.
      </p>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && events.length === 0 && <p>Loading audit log...</p>}
      {!loading && events.length === 0 && !error && (
        <p style={{ color: "#666" }}>No audit events recorded yet.</p>
      )}

      <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: "4px" }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #e0e0e0", textAlign: "left" }}>
            <th style={th}>Time</th>
            <th style={th}>Action</th>
            <th style={th}>Actor</th>
            <th style={th}>Target</th>
            <th style={th}>Outcome</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.audit_event_id} style={{ borderBottom: "1px solid #f0f0f0" }}>
              <td style={{ ...td, color: "#666", whiteSpace: "nowrap" }}>
                {new Date(e.occurred_at).toLocaleString()}
              </td>
              <td style={td}>
                <span style={{ marginRight: "0.3rem" }}>
                  {ACTION_ICONS[e.action] ?? "📝"}
                </span>
                <span style={{ fontFamily: "monospace", fontSize: "0.78rem" }}>
                  {e.action}
                </span>
              </td>
              <td style={{ ...td, fontSize: "0.8rem" }}>
                <div style={{ color: "#555" }}>{e.actor_type}</div>
                <div style={{ fontFamily: "monospace", color: "#999", fontSize: "0.72rem" }}>
                  {e.actor_id.slice(0, 8)}...
                </div>
              </td>
              <td style={{ ...td, fontSize: "0.8rem" }}>
                {e.target_type ? (
                  <>
                    <span style={{ color: "#555" }}>{e.target_type}</span>
                    {e.target_id && (
                      <span style={{ fontFamily: "monospace", color: "#999", marginLeft: "0.3rem", fontSize: "0.72rem" }}>
                        {e.target_id.slice(0, 8)}...
                      </span>
                    )}
                  </>
                ) : "—"}
              </td>
              <td style={td}>
                <span style={{
                  padding: "2px 8px", borderRadius: "3px", fontSize: "0.75rem",
                  background: OUTCOME_COLORS[e.outcome] ?? "#9ca3af", color: "#fff",
                }}>
                  {e.outcome}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {nextCursor && (
        <button
          onClick={() => load(nextCursor)}
          disabled={loading}
          style={{ marginTop: "1rem", padding: "0.5rem 1.5rem", cursor: "pointer" }}
        >
          {loading ? "Loading..." : "Load More"}
        </button>
      )}
    </div>
  );
}

const th: React.CSSProperties = { padding: "0.5rem 0.75rem", fontSize: "0.82rem", color: "#666", fontWeight: 600 };
const td: React.CSSProperties = { padding: "0.45rem 0.75rem", fontSize: "0.85rem" };
