import { useState } from "react";
import { EventsPage } from "./features/alerts/EventsPage";
import { AlertsPage } from "./features/alerts/AlertsPage";
import { IncidentsPage } from "./features/incidents/IncidentsPage";
import { GatewaysPage } from "./features/gateways/GatewaysPage";
import { AssetsPage } from "./features/assets/AssetsPage";
import { ProposalsPage } from "./features/proposals/ProposalsPage";
import { AuditPage } from "./features/audit/AuditPage";

type Page = "events" | "alerts" | "incidents" | "gateways" | "assets" | "proposals" | "audit";

const NAV_ITEMS: { key: Page; label: string; group?: string }[] = [
  { key: "events",    label: "Events",    group: "Telemetry" },
  { key: "gateways",  label: "Gateways",  group: "Telemetry" },
  { key: "assets",    label: "Assets",    group: "Telemetry" },
  { key: "alerts",    label: "Alerts",    group: "Detection" },
  { key: "incidents", label: "Incidents", group: "Detection" },
  { key: "proposals", label: "Proposals", group: "Response" },
  { key: "audit",     label: "Audit Log", group: "Response" },
];

function App() {
  const [page, setPage] = useState<Page>("events");

  // Group nav items
  const groups = Array.from(new Set(NAV_ITEMS.map((i) => i.group)));

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", minHeight: "100vh", display: "flex" }}>
      {/* Sidebar */}
      <nav style={{
        width: "220px",
        background: "#1a1a2e",
        color: "#e0e0e0",
        padding: "1rem 0",
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
      }}>
        <div style={{ padding: "0 1.25rem 1rem", borderBottom: "1px solid #2d2d4a", marginBottom: "0.5rem" }}>
          <h1 style={{ margin: 0, fontSize: "1.3rem", color: "#fff", letterSpacing: "-0.5px" }}>Ascense</h1>
          <p style={{ margin: "3px 0 0", fontSize: "0.75rem", color: "#666" }}>Cyber Defense Platform</p>
        </div>

        {groups.map((group) => (
          <div key={group} style={{ marginBottom: "0.25rem" }}>
            <div style={{
              padding: "0.4rem 1.25rem 0.2rem",
              fontSize: "0.68rem",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              color: "#4a4a6e",
              fontWeight: 600,
            }}>
              {group}
            </div>
            {NAV_ITEMS.filter((i) => i.group === group).map((item) => (
              <button
                key={item.key}
                onClick={() => setPage(item.key)}
                style={{
                  display: "block",
                  width: "100%",
                  padding: "0.55rem 1.25rem",
                  border: "none",
                  background: page === item.key ? "#16213e" : "transparent",
                  color: page === item.key ? "#4fc3f7" : "#b0b0cc",
                  textAlign: "left",
                  cursor: "pointer",
                  fontSize: "0.9rem",
                  borderLeft: page === item.key ? "3px solid #4fc3f7" : "3px solid transparent",
                  transition: "all 0.1s",
                }}
              >
                {item.label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* Main content */}
      <main style={{ flex: 1, padding: "2rem", background: "#f4f6f9", overflowY: "auto", minHeight: "100vh" }}>
        {page === "events"    && <EventsPage />}
        {page === "alerts"    && <AlertsPage />}
        {page === "incidents" && <IncidentsPage />}
        {page === "gateways"  && <GatewaysPage />}
        {page === "assets"    && <AssetsPage />}
        {page === "proposals" && <ProposalsPage />}
        {page === "audit"     && <AuditPage />}
      </main>
    </div>
  );
}

export default App;
