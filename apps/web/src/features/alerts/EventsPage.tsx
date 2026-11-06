import { useEffect, useState } from "react";
import { api, type EventRecord, type Page as PageT } from "../../api/client";

export function EventsPage() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async (cursor?: string) => {
    setLoading(true);
    try {
      const data: PageT<EventRecord> = await api.listEvents(cursor ?? undefined);
      setEvents(cursor ? [...events, ...data.items] : data.items);
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
      <h2 style={{ marginTop: 0 }}>Network Events</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && events.length === 0 && <p>Loading events...</p>}
      {!loading && events.length === 0 && !error && (
        <p style={{ color: "#666" }}>No events yet. Start the gateway simulator to generate events.</p>
      )}

      <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: "4px" }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #e0e0e0", textAlign: "left" }}>
            <th style={th}>Observed At</th>
            <th style={th}>Sensor</th>
            <th style={th}>Source IP</th>
            <th style={th}>Destination</th>
            <th style={th}>Port</th>
            <th style={th}>Direction</th>
            <th style={th}>Asset Resolution</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const net = e.data?.network as Record<string, unknown> | undefined;
            return (
              <tr key={e.event_id} style={{ borderBottom: "1px solid #eee" }}>
                <td style={td}>{new Date(e.observed_at).toLocaleString()}</td>
                <td style={td}>{e.sensor_name}:{e.sensor_instance_id}</td>
                <td style={td}>{net?.source_ip as string ?? "-"}</td>
                <td style={td}>{net?.destination_ip as string ?? "-"}</td>
                <td style={td}>{net?.destination_port as number ?? "-"}</td>
                <td style={td}>{net?.direction as string ?? "-"}</td>
                <td style={td}>
                  <span style={e.asset_resolution_status === "UNRESOLVED" ? { color: "#f59e0b" } : { color: "#22c55e" }}>
                    {e.asset_resolution_status}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {nextCursor && (
        <button onClick={() => load(nextCursor)} style={{ marginTop: "1rem", padding: "0.5rem 1rem", cursor: "pointer" }}>
          Load More
        </button>
      )}
    </div>
  );
}

const th: React.CSSProperties = { padding: "0.5rem 0.75rem", fontSize: "0.85rem", color: "#666" };
const td: React.CSSProperties = { padding: "0.5rem 0.75rem", fontSize: "0.85rem" };
