import { useEffect, useState } from "react";
import { api, type Incident, type Page as PageT } from "../../api/client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Proposal {
  proposal_id: string;
  incident_id: string;
  action_type: string;
  target: Record<string, unknown>;
  status: string;
  reason: string | null;
  created_by: string;
  evidence_ids: string[];
  affected_asset_ids: string[];
  expires_at: string | null;
  created_at: string;
}

interface Approval {
  approval_id: string;
  decision: string;
  reason: string | null;
  approver_id: string;
  status: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

const PROPOSAL_STATUS_COLORS: Record<string, string> = {
  DRAFT: "#9ca3af",
  PENDING_APPROVAL: "#f59e0b",
  SUBMITTED: "#3b82f6",
  POLICY_EVALUATION: "#8b5cf6",
  APPROVED: "#22c55e",
  REJECTED: "#dc2626",
  EXPIRED: "#6b7280",
  CANCELLED: "#6b7280",
};

const DECISION_COLORS: Record<string, string> = {
  APPROVED: "#22c55e",
  REJECTED: "#dc2626",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loadProposals(incidentId: string): Promise<Proposal[]> {
  const data = await api.get<{ items: Proposal[] }>(
    `/api/v1/incidents/${incidentId}/action-proposals`
  );
  return data.items;
}

async function loadApprovals(proposalId: string): Promise<Approval[]> {
  const data = await api.get<{ items: Approval[] }>(
    `/api/v1/action-proposals/${proposalId}/approvals`
  );
  return data.items;
}

// ---------------------------------------------------------------------------
// ProposalsPage
// ---------------------------------------------------------------------------

export function ProposalsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [proposals, setProposals] = useState<Record<string, Proposal[]>>({});
  const [approvals, setApprovals] = useState<Record<string, Approval[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedProposal, setExpandedProposal] = useState<string | null>(null);
  const [approving, setApproving] = useState<string | null>(null);
  const [approvalReason, setApprovalReason] = useState("");

  useEffect(() => {
    setLoading(true);
    api.listIncidents()
      .then(async (data: PageT<Incident>) => {
        setIncidents(data.items);
        // Load proposals for all open incidents
        const openIncidents = data.items.filter(
          (i) => !["RESOLVED", "CLOSED"].includes(i.status)
        );
        const allProposals: Record<string, Proposal[]> = {};
        await Promise.all(
          openIncidents.map(async (inc) => {
            try {
              allProposals[inc.incident_id] = await loadProposals(inc.incident_id);
            } catch {
              allProposals[inc.incident_id] = [];
            }
          })
        );
        setProposals(allProposals);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, []);

  const toggleProposal = async (proposalId: string) => {
    if (expandedProposal === proposalId) {
      setExpandedProposal(null);
      return;
    }
    setExpandedProposal(proposalId);
    if (!approvals[proposalId]) {
      try {
        const loaded = await loadApprovals(proposalId);
        setApprovals((prev) => ({ ...prev, [proposalId]: loaded }));
      } catch {
        setApprovals((prev) => ({ ...prev, [proposalId]: [] }));
      }
    }
  };

  const handleDecision = async (proposalId: string, decision: "APPROVED" | "REJECTED") => {
    if (!approvalReason.trim()) {
      alert("A reason is required for approval decisions.");
      return;
    }
    setApproving(proposalId);
    try {
      await api.post(`/api/v1/action-proposals/${proposalId}/approvals`, {
        decision,
        reason: approvalReason.trim(),
      });
      setApprovalReason("");
      // Reload approvals for this proposal
      const loaded = await loadApprovals(proposalId);
      setApprovals((prev) => ({ ...prev, [proposalId]: loaded }));
      // Reload all proposals
      for (const incidentId of Object.keys(proposals)) {
        try {
          const updated = await loadProposals(incidentId);
          setProposals((prev) => ({ ...prev, [incidentId]: updated }));
        } catch { /* ignore */ }
      }
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setApproving(null);
    }
  };

  const handleRevoke = async (proposalId: string, approvalId: string) => {
    const reason = window.prompt("Enter reason for revocation:");
    if (!reason) return;
    try {
      await api.post(
        `/api/v1/action-proposals/${proposalId}/approvals/${approvalId}/revocations`,
        { reason }
      );
      const loaded = await loadApprovals(proposalId);
      setApprovals((prev) => ({ ...prev, [proposalId]: loaded }));
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const handleCancel = async (proposalId: string) => {
    const reason = window.prompt("Enter reason for cancellation:");
    if (!reason) return;
    try {
      await api.post(`/api/v1/action-proposals/${proposalId}/cancellations`, { reason });
      for (const incidentId of Object.keys(proposals)) {
        try {
          const updated = await loadProposals(incidentId);
          setProposals((prev) => ({ ...prev, [incidentId]: updated }));
        } catch { /* ignore */ }
      }
    } catch (err) {
      alert((err as Error).message);
    }
  };

  // Flatten all proposals across incidents
  const allProposals: Array<{ incident: Incident; proposal: Proposal }> = [];
  for (const incident of incidents) {
    for (const proposal of proposals[incident.incident_id] || []) {
      allProposals.push({ incident, proposal });
    }
  }

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>Action Proposals</h2>
      {error && <div style={{ color: "red" }}>Error: {error}</div>}
      {loading && <p>Loading proposals...</p>}
      {!loading && allProposals.length === 0 && !error && (
        <p style={{ color: "#666" }}>
          No active proposals. Proposals are created during incident response.
        </p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        {allProposals.map(({ incident, proposal }) => (
          <div key={proposal.proposal_id} style={{
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderLeft: `4px solid ${PROPOSAL_STATUS_COLORS[proposal.status] ?? "#999"}`,
            borderRadius: "4px",
            padding: "1rem",
          }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                  {proposal.action_type}
                  <span style={{
                    marginLeft: "0.5rem",
                    padding: "2px 8px",
                    borderRadius: "3px",
                    background: PROPOSAL_STATUS_COLORS[proposal.status] ?? "#999",
                    color: "#fff",
                    fontSize: "0.75rem",
                    fontWeight: 400,
                  }}>
                    {proposal.status}
                  </span>
                </div>
                <div style={{ fontSize: "0.8rem", color: "#666", marginTop: "2px" }}>
                  Incident: {incident.title ?? incident.incident_id.slice(0, 8)}
                  {" · "}
                  By: {proposal.created_by}
                  {" · "}
                  {new Date(proposal.created_at).toLocaleString()}
                </div>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                {proposal.status === "PENDING_APPROVAL" && (
                  <>
                    <button
                      onClick={() => toggleProposal(proposal.proposal_id)}
                      style={{ fontSize: "0.8rem", cursor: "pointer", padding: "4px 10px" }}
                    >
                      {expandedProposal === proposal.proposal_id ? "▲ Hide" : "▼ Review"}
                    </button>
                    <button
                      onClick={() => handleCancel(proposal.proposal_id)}
                      style={{
                        fontSize: "0.8rem", cursor: "pointer", padding: "4px 10px",
                        color: "#dc2626", border: "1px solid #dc2626", background: "transparent",
                      }}
                    >
                      Cancel
                    </button>
                  </>
                )}
                {proposal.status === "APPROVED" && (
                  <button
                    onClick={() => toggleProposal(proposal.proposal_id)}
                    style={{ fontSize: "0.8rem", cursor: "pointer", padding: "4px 10px" }}
                  >
                    {expandedProposal === proposal.proposal_id ? "▲ Hide" : "▼ Approvals"}
                  </button>
                )}
              </div>
            </div>

            {/* Target details */}
            {proposal.target && (
              <div style={{
                marginTop: "0.5rem", padding: "0.4rem 0.6rem",
                background: "#f8f8f8", borderRadius: "3px",
                fontFamily: "monospace", fontSize: "0.78rem", color: "#444",
              }}>
                Target: {JSON.stringify(proposal.target)}
              </div>
            )}
            {proposal.reason && (
              <p style={{ margin: "0.4rem 0 0", fontSize: "0.85rem", color: "#555" }}>
                {proposal.reason}
              </p>
            )}
            {proposal.expires_at && (
              <div style={{ fontSize: "0.75rem", color: "#999", marginTop: "2px" }}>
                Expires: {new Date(proposal.expires_at).toLocaleString()}
              </div>
            )}

            {/* Approval panel */}
            {expandedProposal === proposal.proposal_id && (
              <div style={{
                marginTop: "0.75rem", paddingTop: "0.75rem",
                borderTop: "1px solid #eee",
              }}>
                {/* Existing approvals */}
                {(approvals[proposal.proposal_id] || []).length > 0 && (
                  <div style={{ marginBottom: "0.75rem" }}>
                    <div style={{ fontSize: "0.82rem", fontWeight: 600, marginBottom: "0.3rem" }}>
                      Approval History
                    </div>
                    {(approvals[proposal.proposal_id] || []).map((appr) => (
                      <div key={appr.approval_id} style={{
                        display: "flex", alignItems: "center", gap: "0.5rem",
                        fontSize: "0.8rem", padding: "3px 0",
                      }}>
                        <span style={{
                          padding: "2px 8px", borderRadius: "3px",
                          background: DECISION_COLORS[appr.decision] ?? "#999",
                          color: "#fff", fontSize: "0.72rem",
                        }}>
                          {appr.decision}
                        </span>
                        <span style={{ color: "#444" }}>{appr.reason}</span>
                        <span style={{ color: "#999", marginLeft: "auto" }}>
                          {new Date(appr.created_at).toLocaleString()}
                          {" · "}
                          {appr.status}
                        </span>
                        {appr.status === "APPROVED" && (
                          <button
                            onClick={() => handleRevoke(proposal.proposal_id, appr.approval_id)}
                            style={{
                              fontSize: "0.72rem", cursor: "pointer", padding: "2px 8px",
                              color: "#dc2626", border: "1px solid #dc2626", background: "transparent",
                            }}
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Approval action */}
                {proposal.status === "PENDING_APPROVAL" && (
                  <div>
                    <div style={{ fontSize: "0.82rem", fontWeight: 600, marginBottom: "0.3rem" }}>
                      Record Decision
                    </div>
                    <textarea
                      value={approvalReason}
                      onChange={(e) => setApprovalReason(e.target.value)}
                      placeholder="Reason (required)..."
                      rows={2}
                      style={{
                        width: "100%", boxSizing: "border-box",
                        padding: "6px", fontSize: "0.82rem",
                        border: "1px solid #ddd", borderRadius: "3px",
                        marginBottom: "0.4rem", resize: "vertical",
                      }}
                    />
                    <div style={{ display: "flex", gap: "0.5rem" }}>
                      <button
                        disabled={approving === proposal.proposal_id}
                        onClick={() => handleDecision(proposal.proposal_id, "APPROVED")}
                        style={{
                          padding: "6px 16px", cursor: "pointer",
                          background: "#22c55e", color: "#fff",
                          border: "none", borderRadius: "3px", fontSize: "0.82rem",
                        }}
                      >
                        {approving === proposal.proposal_id ? "..." : "Approve"}
                      </button>
                      <button
                        disabled={approving === proposal.proposal_id}
                        onClick={() => handleDecision(proposal.proposal_id, "REJECTED")}
                        style={{
                          padding: "6px 16px", cursor: "pointer",
                          background: "#dc2626", color: "#fff",
                          border: "none", borderRadius: "3px", fontSize: "0.82rem",
                        }}
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
