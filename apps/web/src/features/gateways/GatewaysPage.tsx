import { useEffect, useState } from "react";
import { api, type Gateway, type Page as PageT, type SensorStatus } from "../../api/client";

const STATUS_COLORS: Record<string, string> = {
  ACTIVE: "#22c55e",
  DEGRADED: "#f59e0b",
  DISCONNECTED: "#dc2626",
  UNREGISTERED: "#9ca3af",
  ENROLLMENT_PENDING: "#3b82f6",
  REVOKED: "#dc2626",
  DECOMMISSIONED: "#6b7280",
  TELEMETRY_STALE: "#ea580c",
};

export function GatewaysPage() {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedGateway, setExpandedGateway] = useState<string | null>(null);
  const [sensors, setSensors] = useState<Record<string, SensorStatus[]>>({});
  const [sensorLoading, setSensorLoading] = useState<string | null>(null);

  useEffect(() => {
    api.listGateways()
      .then((data: PageT<Gateway>) => setGateways(data.items))
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, []);

  const loadSensors = async (gatewayId: string) => {
    setSensorLoading(gatewayId);
    try {
      const data = await api.getGatewaySensors(gatewayId);
      setSensors((prev) => ({ ...prev, [gatewayId]: data.sensors }));
    } catch {
      try {
        const health = await api.getTelemetryHealth(gatewayId);
        setSensors((prev) => ({ ...prev, [gatewayId]: health.sensors || [] }));
      } catch {
        setSensors((prev) => ({ ...prev, [gatewayId]: [] }));
      }
    } finally {
      setSensorLoading(null);
    }
  };

  const toggleExpand = (gatewayId: string) => {
    if (expandedGateway === gatewayId) {
      setExpandedGateway(null);
    } else {
      setExpandedGateway(gatewayId);
      if (!sensors[gatewayId]) {
        loadSensors(gatewayId);
      }
    }
  };

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Gateways</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && <p>Loading gateways...</p>}
      {!loading && gateways.length === 0 && !error && (
        <p style={{ color: "#666" }}>No gateways registered. Enroll a gateway to begin.</p>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: "1rem" }}>
        {gateways.map((g) => (
          <div key={g.gateway_id} style={{
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderRadius: "4px",
            padding: "1rem",
          }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}
              onClick={() => toggleExpand(g.gateway_id)}
            >
              <span style={{
                width: 10, height: 10, borderRadius: "50%",
                background: STATUS_COLORS[g.status] ?? "#999",
                boxShadow: g.status === "TELEMETRY_STALE" ? "0 0 6px #ea580c" : "none",
              }} />
              <strong>{g.name}</strong>
              {g.status === "TELEMETRY_STALE" && (
                <span style={{
                  marginLeft: "0.25rem", fontSize: "0.7rem", color: "#ea580c",
                  background: "#fef3c7", padding: "2px 6px", borderRadius: "3px",
                }}>
                  STALE
                </span>
              )}
              <span style={{ marginLeft: "auto", fontSize: "0.7rem", color: "#999" }}>
                {expandedGateway === g.gateway_id ? "▼" : "▶"}
              </span>
            </div>
            <div style={{ marginTop: "0.5rem", fontSize: "0.8rem", color: "#666" }}>
              <div>Status: <span style={{ fontWeight: 600 }}>{g.status}</span></div>
              <div>Config v{g.config_version}</div>
              <div>Last heartbeat: {g.last_heartbeat_at ? new Date(g.last_heartbeat_at).toLocaleString() : "Never"}</div>
              <div style={{ marginTop: "0.25rem", fontFamily: "monospace", fontSize: "0.75rem", color: "#999" }}>
                {g.gateway_id.slice(0, 8)}...
              </div>
            </div>

            {/* Sensor health section (expandable) */}
            {expandedGateway === g.gateway_id && (
              <div style={{
                marginTop: "0.75rem",
                paddingTop: "0.75rem",
                borderTop: "1px solid #eee",
              }}>
                <div style={{ fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.4rem" }}>
                  Sensors
                </div>
                {sensorLoading === g.gateway_id && (
                  <div style={{ fontSize: "0.8rem", color: "#999" }}>Loading sensors...</div>
                )}
                {!sensorLoading && (sensors[g.gateway_id] || []).length === 0 && (
                  <div style={{ fontSize: "0.8rem", color: "#999" }}>No sensors reporting.</div>
                )}
                {(sensors[g.gateway_id] || []).map((s) => {
                  const sensorColor =
                    s.status === "HEALTHY" ? "#22c55e" :
                    s.status === "DEGRADED" ? "#f59e0b" :
                    s.status === "SENSOR_FAILURE" ? "#dc2626" :
                    "#9ca3af";
                  return (
                    <div key={s.instance_id} style={{
                      display: "flex", alignItems: "center", gap: "0.4rem",
                      padding: "0.25rem 0", fontSize: "0.8rem",
                    }}>
                      <span style={{
                        width: 8, height: 8, borderRadius: "50%",
                        background: sensorColor,
                      }} />
                      <span>{s.name}:{s.instance_id}</span>
                      <span style={{
                        marginLeft: "auto", fontSize: "0.7rem",
                        color: sensorColor, fontWeight: 600,
                      }}>
                        {s.status}
                      </span>
                      {s.last_event_at && (
                        <span style={{ fontSize: "0.7rem", color: "#999" }}>
                          {new Date(s.last_event_at).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
