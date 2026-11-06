import { useEffect, useState } from "react";
import { api, type Asset, type Page as PageT } from "../../api/client";

const CRITICALITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#f59e0b",
  low: "#3b82f6",
};

export function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listAssets()
      .then((data: PageT<Asset>) => setAssets(data.items))
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Protected Assets</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && <p>Loading assets...</p>}
      {!loading && assets.length === 0 && !error && (
        <p style={{ color: "#666" }}>No assets registered. Run the seed script to create test assets.</p>
      )}

      <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: "4px" }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #e0e0e0", textAlign: "left" }}>
            <th style={th}>Hostname</th>
            <th style={th}>Type</th>
            <th style={th}>Criticality</th>
            <th style={th}>Status</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.asset_id} style={{ borderBottom: "1px solid #eee" }}>
              <td style={td}>{a.hostname ?? "-"}</td>
              <td style={td}>{a.asset_type}</td>
              <td style={td}>
                <span style={{
                  padding: "2px 8px", borderRadius: "3px", fontSize: "0.75rem",
                  background: CRITICALITY_COLORS[a.criticality] ?? "#999", color: "#fff",
                }}>
                  {a.criticality}
                </span>
              </td>
              <td style={td}>{a.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const th: React.CSSProperties = { padding: "0.5rem 0.75rem", fontSize: "0.85rem", color: "#666" };
const td: React.CSSProperties = { padding: "0.5rem 0.75rem", fontSize: "0.85rem" };
