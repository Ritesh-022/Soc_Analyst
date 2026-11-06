**Autonomous Cyber Defense Platform**

_Architecture, Design, ML, Agentic AI and Implementation Specification (Revision 2: scope reset and commercial reframing)_

| **Item**              | **Detail**                                                                                                                                                                                                                                                                                                                              |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Product**           | Autonomous Cyber Defense Platform: network, application and data security in one SaaS product                                                                                                                                                                                                                                           |
| **Architecture**      | Edge security gateway + cloud platform + ML detection + model fusion + agentic investigation + game-theoretic response + policy safety gate + continuous verification                                                                                                                                                                   |
| **Layers protected**  | Network (firewall/IDS/IPS), Application/API (WAF, API security), Data (discovery, access monitoring, exfiltration detection)                                                                                                                                                                                                            |
| **Backend**           | Python, FastAPI, PostgreSQL (+pgvector), Redis, event streaming (Kafka or NATS)                                                                                                                                                                                                                                                         |
| **ML**                | scikit-learn, XGBoost, LightGBM, PyTorch; MLflow for registry; ONNX for edge inference                                                                                                                                                                                                                                                  |
| **Agents / LLM**      | LangGraph + provider abstraction (local Ollama / hosted API); RAG over a security knowledge base                                                                                                                                                                                                                                        |
| **Frontend**          | React + TypeScript + Vite, real-time dashboard (WebSocket)                                                                                                                                                                                                                                                                              |
| **Deployment**        | Docker; Kubernetes when scale requires; AWS / Azure / GCP; optional on-premises                                                                                                                                                                                                                                                         |
| **Market**            | India first, then global; colleges, SMBs, manufacturing/IoT, healthcare, financial services (later)                                                                                                                                                                                                                                     |
| **Status**            | Design specification. All figures are illustrative targets, not measured results.                                                                                                                                                                                                                                                       |
| **Revision 2 status** | Scope reset after an independent commercial and technical review. The MVP is an AI incident analyst with safety-gated response on the customer's existing firewall. The custom gateway, the application and data layers and the game-theoretic engine are deferred. See Revision 2 below; it takes precedence over every other section. |

# **REVISION 2: SCOPE RESET AND COMMERCIAL REFRAMING**

## **R1. Purpose, Status and Precedence**

This revision applies the findings of an independent commercial and technical review. The review found a well-engineered architecture with no customer evidence, a scope far beyond the team's capacity, several internal inconsistencies, and a product definition that overlaps four crowded categories at once (firewall/IDS, WAF, data security and AI SOC tooling). No technical content has been deleted. Material that is not needed to test the core proposition is re-labelled Tier 2 (build after paid pilots) or Tier 3 (research module, not for sale).

Where Revision 2 conflicts with any other section, including Part N, **Revision 2 takes precedence**. Every commercial statement in this revision is a **hypothesis** until the validation gates in R6 are passed. Nothing in this document is evidence that customers will buy the product.

| **Review finding**                                                                                                  | **Correction in this revision**                                      |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **No customer evidence and no pricing**                                                                             | Customer, channel and pricing hypotheses (R5); validation gates (R6) |
| **Phase plan adds up to 59 weeks for a full team; the team has 4 people against 8 listed roles**                    | Tiered scope (R3), simplified stack (R4), realistic plan (R7)        |
| **Product overlaps firewall, WAF, UEBA, data security and AI SOC at once**                                          | One narrow product definition (R2)                                   |
| **Fusion averages M6, a risk predictor, into the attack score although section 15.6 forbids using it for blocking** | M6 removed from detection fusion (R8.1); sections 15.6 and 18 edited |
| **Own pilot data is called "the moat" while training is isolated per tenant**                                       | Moat claim withdrawn; consent rules (R8.2); section 13 edited        |
| **Game-engine parameters are estimates and the safety gate already limits the action set**                          | Game engine demoted to Tier 3 (R8.4); Part G marked                  |
| **Alert volume and cost per investigation are not budgeted**                                                        | Alert budget and cost rules (R8.3)                                   |

## **R2. Reframed Product Definition**

**Product statement.** An AI incident analyst and safety-gated response layer for the firewall and IDS that an organisation already runs. It converts raw alerts into evidence-cited incidents, proposes a proportionate response, executes only approved, time-limited and reversible actions through the customer's existing firewall, verifies the outcome, and keeps an audit trail.

**Not in the MVP.** A replacement firewall, an inline gateway the customer must place in front of production traffic, a WAF, and a data-security product.

**Preserved.** The deterministic floor, the policy safety gate, verification, explainability, the audit trail, prompt-injection defences, the honest-claims rules of Part M and the ablation methodology of section 17.

**Proposition to test:** a sysadmin or MSP will pay a recurring fee for AI-written incident reports plus one-tap, reversible, verified response on the firewall they already own.

## **R3. Scope Tiers**

| **Tier**                            | **Components**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | **Condition to enter**                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| **Tier 1 (MVP)**                    | Passive Suricata sensor (EVE JSON) and firewall syslog ingestion; event normalisation; deterministic correlation into incidents; M2 classifier and M3 statistical DDoS detector as optional enrichers, kept only if they beat Suricata-only detection in the ablation; one read-only LLM investigation agent with cited evidence; safety gate; response adapter for one firewall platform (chosen from what pilot MSPs run; pfSense/OPNsense is the default candidate); actions limited to L0 to L2, with L3 only after human approval; approval by Slack, WhatsApp or email; verification; audit log; weekly report and an incident-report export for Indian reporting duties | None                                                                                     |
| **Tier 2**                          | Custom edge gateway (nftables, eBPF/XDP, Zeek); M1 anomaly, M4 C2 and M5 UEBA models; TLS metadata features; multi-tenant hardening; second and third firewall adapters; SOC 2 or ISO 27001 preparation; local-LLM packaging                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Gate G3 (three paid pilots) and gate G4 (two customers running L2 actions in production) |
| **Tier 3 (research, not for sale)** | Game-theoretic engine (Part G); M6 risk prediction; M7 to M9 and the application/API and data layers (Part E); security knowledge graph (section 24); honeypots and deception; Dempster-Shafer and other advanced fusion                                                                                                                                                                                                                                                                                                                                                                                                                                                       | A Tier 2 customer asks for the capability, and an ablation shows a measurable benefit    |

## **R4. Simplified MVP Architecture and Stack**

Passive Suricata sensor (mirror port or tap) → event normaliser → incident correlator → LLM investigation agent (read-only tools) → proposed response → safety gate → human approval → firewall adapter running on the customer side → verification → audit log and weekly report.

| **Area**             | **Original specification**                                    | **MVP (Revision 2)**                                              |
| -------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Traffic and IDS**  | Custom gateway: nftables, eBPF/XDP, Suricata, Zeek, WAF       | Suricata only, passive; Zeek deferred to Tier 2                   |
| **Enforcement**      | Gateway enforces locally                                      | Adapter calls the customer's existing firewall API after approval |
| **Event transport**  | Kafka or NATS                                                 | PostgreSQL-backed queue or Redis streams                          |
| **Storage**          | PostgreSQL, TimescaleDB or ClickHouse, Neo4j, pgvector, Redis | PostgreSQL (pgvector only if retrieval is needed)                 |
| **Orchestration**    | Kubernetes, staged releases                                   | Docker Compose on one VM per pilot or shared tenant               |
| **Agents**           | LangGraph multi-agent system                                  | One investigation agent with a fixed, read-only tool set          |
| **Model operations** | MLflow registry, drift pipelines                              | Versioned model files plus a reproducible evaluation script       |
| **Decision**         | Game-theoretic engine                                         | Deterministic ladder (section 36) plus safety gate (section 37)   |

## **R5. Customers, Channel and Pricing (Hypotheses)**

| **Item**                            | **Hypothesis (unvalidated)**                                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **First buyer**                     | MSPs and IT-services firms that serve SMBs and colleges. Local IT partners are the usual route to SMBs, so the channel comes before direct sales.                                    |
| **Design partners**                 | RNSIT and neighbouring colleges, with written permission before any traffic is captured. A free pilot has a fixed end date and signed success criteria; otherwise it does not start. |
| **End user and approver**           | Sysadmin or IT head approves actions; finance or the institution head approves spend.                                                                                                |
| **Pricing to test**                 | Wholesale per site per month to the MSP, in a range of about Rs 5,000 to 25,000, tiered by size. This range is a starting point for price conversations, not a finding.              |
| **Cost tracking**                   | Record LLM cost per investigation, compute per site and support hours per site from the first pilot. Gross margin is unknown until these are measured.                               |
| **Buyer objections to prepare for** | Liability for a wrong block; why not the firewall's built-in IPS; an unproven vendor; data leaving the premises.                                                                     |

**Competitive context (to be re-verified before external use).** Autonomous response is already sold by Darktrace. AI SOC analysts are a heavily funded category (for example Torq, 7AI, Prophet Security and Dropzone AI), and these products integrate with existing tools rather than requiring new hardware. Firewall vendors (Fortinet, Palo Alto, Sophos, Cisco) bundle IPS and ML. Open-source alternatives include Suricata, Zeek, Security Onion, Wazuh, CrowdSec and pfSense/OPNsense. Indian vendors include Seqrite and Quick Heal.

**Differentiation hypotheses.** Price and local support; data residency with a local-model option; approvals through WhatsApp and Slack; incident evidence formatted for Indian reporting duties (the current CERT-In directions must be checked and cited); verified, reversible response with a full audit trail. None of these counts as a differentiator until a customer says so.

## **R6. Validation Gates**

| **Gate** | **Evidence required**                                                                                                              | **Owner (to assign)**  | **If not met**                                                     |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------ |
| **G0**   | At least 15 customer-discovery interviews (10 IT heads, 5 MSPs) with written notes on current tools, spend and who approves blocks | Business owner         | Re-scope the buyer before building further                         |
| **G1**   | Written permission to capture passive logs at two or more sites                                                                    | Team lead              | Use replayed datasets only; do not claim pilot results             |
| **G2**   | Four weeks of shadow-mode results: fewer incidents to review, and no incident missed that a human later confirmed                  | ML and security owners | Fix detection or correlation before any enforcement                |
| **G3**   | At least three signed paid pilots (any amount) with written success criteria                                                       | Business owner         | After three failed attempts per segment, stop Tier 2 and re-scope  |
| **G4**   | At least two customers enable L2 actions in production                                                                             | Safety-gate owner      | Stay recommendation-only; investigate the trust barrier            |
| **G5**   | At least two pilots convert to recurring contracts                                                                                 | Business owner         | Treat as a project, not a business, and decide whether to continue |

## **R7. Revised Delivery Plan**

| **Phase**                | **Weeks (assumed)** | **Deliverables**                                                                                                             | **Exit condition**                                          |
| ------------------------ | ------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **P0 Discovery**         | 1 to 3 (parallel)   | Interview programme (G0), data permissions (G1), lab replay environment                                                      | G0 and G1 evidence recorded                                 |
| **P1 Thin slice**        | 1 to 10             | Suricata EVE ingestion, normaliser, incident correlator, read-only LLM report with cited evidence, tests on replayed attacks | Reports match human review on the replay set                |
| **P2 Shadow pilot**      | 10 to 14            | Monitor-only at two or three sites; measure incidents, false incidents per day, analyst minutes per incident                 | G2 met                                                      |
| **P3 Approved response** | 14 to 20            | Safety gate, one firewall adapter, approval flow, TTL and rollback, verification, audit log                                  | Safety-gate test suite passes; zero unsafe actions in tests |
| **P4 Paid pilots**       | 18 to 30            | Convert shadow sites to paid pilots; weekly report; incident-report export                                                   | G3 met                                                      |
| **P5 Decision**          | 30                  | Review all gates, unit economics and the Tier 2 backlog                                                                      | Go to Tier 2, re-scope, or stop                             |

The plan assumes four students working part-time around coursework and examinations, so wall-clock time is about 30 weeks. This is a planning assumption and must be revised after P1. The earlier 59-week full-feature plan is withdrawn.

## **R8. Technical Corrections Introduced in Revision 2**

- **R8.1 Fusion scope.** Fusion averages detection models only (M1 to M5). M6 estimates future exposure and is used only to weight prioritisation. Where a specialist model fires in its own category (for example M3 for DDoS), the specialist is trusted for that category, as section 18.1 already states. Sections 15.6 and 18 are edited to match.
- **R8.2 Data moat versus tenant isolation.** Training is per tenant by default, so no cross-customer data moat is assumed. Pooled learning is allowed only from customer-consented, anonymised aggregates. The claim that own pilot data "builds the moat" is withdrawn and replaced by a hypothesis: a dataset of verified response outcomes may become valuable if customers consent to its use.
- **R8.3 Alert and cost budget.** A site with 10 million flow records a day and a 0.1% false-positive rate would raise 10,000 false flow-level alerts a day. Therefore the unit of evaluation and of LLM work is the incident, not the flow; a per-site daily cap on agent investigations is set from the measured cost per investigation; incidents above the cap are queued by deterministic priority; and every pilot records false incidents per day and analyst minutes per incident.
- **R8.4 Game engine demoted.** The deterministic ladder and safety gate decide in the MVP. The engine is a Tier 3 research comparison and never randomises enforcement.
- **R8.5 Passive first.** The MVP is passive and enforces through the customer's existing firewall. An inline gateway (Tier 2) needs a written fail-open or fail-closed design, high-availability design and throughput tests before any customer installs it.
- **R8.6 Encrypted traffic.** Detection claims are limited to what metadata and handshake features can show. TLS decryption stays off by default, and the evidence register records which attack classes are not visible in encrypted traffic.
- **R8.7 Asset criticality.** Asset-aware risk (section 19) depends on labels customers rarely maintain. The MVP asks for three coarse asset tiers in a short onboarding step, and defaults to the more conservative action when an asset is unlabelled. Automatic asset discovery is Tier 2.
- **R8.8 Licences and feeds.** Before commercial use, record the licence and cost of every rule set, threat feed and library (including commercial Suricata rule subscriptions) in the source register of section 75.
- **R8.9 No cloud-originated enforcement.** In the MVP the cloud never pushes enforcement commands. The customer-side adapter acts only on actions that a human approved, and verifies their signature before executing. This reduces the platform's own supply-chain risk.
- **R8.10 Liability and operations.** Pilots start in shadow mode, have a customer-controlled kill switch and allow-list, and have written terms that define who is responsible for an approved action. Legal review of these terms is required before the first paid pilot.

## **R9. Revised Success and Kill Criteria**

**Success.** The criteria of section 59 stand, with the business outcome tightened: three signed paid pilots, two conversions to recurring contracts, two customers running L2 actions in production, a measured reduction in analyst minutes per incident, and zero unsafe actions in testing and in pilots.

**Kill or re-scope triggers.** Stop Tier 2 work and re-scope if any of the following occurs:

- No paid pilot is signed after three attempts in each of two customer segments.
- Shadow mode shows no meaningful reduction in review effort, or a human-confirmed miss that the pipeline cannot explain.
- No customer will allow even reversible L2 actions after a full pilot.
- Cost per investigation and support hours per site leave no positive gross margin at any price customers accept.

## **R10. Revised Top Risks**

| **Risk**                                        | **Why it matters**                                          | **Mitigation**                                                                  |
| ----------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **Nobody pays; pilots never convert**           | Security buyers favour known vendors, and free pilots drift | Paid pilots with end dates (G3); MSP channel                                    |
| **Customers never grant enforcement rights**    | Without it the product is a monitor                         | Reversible, TTL-limited L2 actions with one-tap approval; shadow evidence first |
| **A false positive causes an outage**           | Churn and liability                                         | Shadow mode, safety gate, kill switch, written terms                            |
| **Scope creep returns**                         | Nothing ships                                               | Tier labels; Tier 3 needs a customer request and an ablation                    |
| **Models do not transfer from public datasets** | Poor real-world accuracy                                    | Evaluate on pilot data early; keep Suricata-only baseline                       |
| **Team capacity**                               | Four students with coursework                               | Thin slice; named owners for gate, audit and enforcement tests                  |
| **An incumbent ships the same feature**         | Differentiation disappears                                  | Own the MSP channel and the India-specific evidence workflow                    |

## **R11. Information Still Missing**

This revision does not invent facts. The following are unknown and must be supplied before the plan is final:

- Budget and runway, and any cloud or LLM credits available.
- Ownership of intellectual property between the team and the college.
- What code already exists, as opposed to design.
- Whether written permission exists to capture real traffic at any site.
- Each team member's production network-security and operations experience, which decides who can own the enforcement and safety-gate work.
- Legal advice on liability, data-protection duties and Indian incident-reporting duties.

**Status:** Revision 2 is a plan to generate evidence. It does not show that the platform works or that customers will pay.

# **PART A: VISION AND FOUNDATIONS**

## **1\. Project Vision**

The goal is not to build one more intrusion detection tool. The goal is to build a platform that **detects, understands, decides, responds and verifies** security events across the network, the application and the data, with a human always able to stay in control.

Most security products stop at an alert. A person must then investigate, decide and act, often at night, often without context. This platform closes the loop: it investigates automatically, chooses the least disruptive effective response, enforces it through a safety gate, and checks that the attack really stopped and that legitimate users were not harmed.

The key principle of the whole design is:

**Deterministic security is the floor. AI adds judgement above it. A safety gate sits between every AI decision and every enforcement action. Every action is logged, explainable and reversible where possible.**

## **2\. Core Problem**

A conventional security setup works like this:

```
Attack happens
   -> Firewall allows it (no matching rule)
   -> Alerts pile up in different tools
   -> Analyst is notified (late)
   -> Manual investigation
   -> Manual response
   -> Nobody verifies containment
```

This produces specific, measurable problems:

- **Static rules miss new attacks.** Signatures and ACLs only cover what is already known.
- **Alert overload.** Many alerts belong to one campaign but arrive as unrelated events.
- **Slow investigation.** Correlating logs, assets, users and threat intelligence is manual work.
- **Wrong-size responses.** Too aggressive blocks legitimate users or critical services; too slow lets attackers move.
- **No verification.** After a block, nobody confirms the attacker did not pivot to another IP, port, protocol or application path.
- **Data is the real target.** Most incidents end with data accessed, copied or stolen, yet network tools rarely understand where sensitive data lives or who touches it.
- **Small organizations have no security team.** They cannot staff a 24x7 security operations centre.

The platform changes the workflow to:

```
Traffic / requests / data access
   -> Deterministic controls (firewall, WAF, access policy)
   -> Feature extraction
   -> Multiple ML models -> Fusion -> Threat score
   -> Agentic investigation (correlate, enrich, reconstruct)
   -> Response selection (MVP: rule-based ladder; game-theoretic engine deferred, see Part G)
   -> Policy safety gate (+ human approval when needed)
   -> Enforcement (firewall / WAF / identity / database)
   -> Verification -> Feedback -> Learning
```

## **3\. Design Philosophy**

### **3.1 Deterministic first, AI second**

The traditional firewall, WAF and access controls always run. If the cloud, the ML models or the LLM are unavailable, the gateway keeps enforcing local policy. AI can only add protection or recommend changes; it can never be the only control.

### **3.2 AI never controls enforcement directly**

```
Correct:   Detection -> Investigation -> Decision -> Safety Gate -> Enforcement
Incorrect: Detection -> LLM -> Firewall command
```

### **3.3 Every decision is explainable and auditable**

For each action the platform stores which models fired, their scores, what the agents found, which strategy was selected and why, which safety checks passed, who approved it and what happened afterwards.

### **3.4 Untrusted input stays untrusted**

Logs, packet payloads, HTTP bodies, DNS names, usernames and threat-feed text can all be attacker-controlled. They are treated as data, never as instructions to the LLM agents (prompt-injection defence, see section 29).

### **3.5 Metadata first, content only when necessary**

The platform analyses flow records, request metadata, query metadata and classification labels. It avoids copying raw sensitive content (patient records, card numbers) into the cloud. This is essential for healthcare, finance and privacy law compliance.

### **3.6 Least disruption**

The response engine prefers the mildest effective action (monitor, rate-limit, challenge) before block, quarantine or isolation, and every blocking action has an expiry time by default.

### **3.7 Honest claims**

The product never claims to be "100% secure". It claims measurable improvements: lower time to detect, investigate and contain; fewer false positives; less analyst workload.

## **4\. Product Scope: Three Protection Layers**

| **Layer**             | **What it protects**                                             | **Main controls and detections**                                                                                                              |
| --------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network**           | Traffic entering, leaving and moving inside the customer network | Stateful firewall, IDS/IPS, rate limiting, segmentation, DDoS/scan/brute-force/botnet/lateral-movement detection                              |
| **Application / API** | Web applications, APIs, logins, sessions                         | WAF with OWASP rules, API schema validation, bot and credential-stuffing detection, broken-access-control patterns, request anomaly detection |
| **Data**              | Databases, file stores, object storage, data in motion           | Data discovery and classification, data-access monitoring (UEBA), exfiltration detection, encryption and exposure posture checks              |

**Revision 2:** In the MVP only the network layer is in scope, delivered as analysis and response on the customer's existing firewall. The application/API and data layers are Tier 3 (see R3).

### **4.1 Non-goals (first versions)**

- Replacing large enterprise firewall vendors across the board.
- Full endpoint detection and response (EDR) or antivirus.
- Decrypting all TLS traffic by default (metadata and handshake features are used instead).
- Fully autonomous action on critical systems without human approval.
- Claiming detection of every possible attack.
- Shipping or operating a custom inline gateway in the MVP.
- Any randomised or non-deterministic enforcement, for example blocking a random fraction of identical requests.
- Claiming a competitive advantage that no customer has confirmed.

## **5\. Target Customers and Deployment Modes**

| **Segment**                     | **Why they need it**                                              | **Notes**                                                |
| ------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------- |
| **Colleges and universities**   | Large networks, little security staff, many students and devices  | Easiest first pilots; reference customers                |
| **SMBs and software companies** | Need enterprise-grade protection and audit evidence without a SOC | Reach through MSPs and IT service providers              |
| **Manufacturing / IoT / OT**    | Flat networks, legacy devices, high downtime cost                 | Monitor and segmentation first; never auto-stop machines |
| **Healthcare**                  | Medical devices, patient-data systems                             | Human approval for device actions; on-prem option        |
| **Financial services**          | Payment and customer data                                         | Later; heavy audit and certification requirements        |

| **Deployment mode**             | **Where it runs**                                           | **Use when**                             |
| ------------------------------- | ----------------------------------------------------------- | ---------------------------------------- |
| **SaaS + edge gateway**         | Light gateway on customer network; analysis in vendor cloud | Default for SMBs and colleges            |
| **Hybrid**                      | Gateway + customer-region cloud tenant                      | Data-residency needs                     |
| **On-premises / private cloud** | Entire stack inside customer environment                    | Healthcare, banking, regulated customers |
| **Monitor-only (passive)**      | Mirror/SPAN port, no enforcement                            | First pilots and trust-building          |

**Revision 2:** the first buyer is expected to be an MSP or IT-services firm serving SMBs and colleges. Colleges are design partners; a free pilot needs a fixed end date and signed success criteria (R5, R6).

# **PART B: SYSTEM ARCHITECTURE**

**Revision 2:** the edge gateway described in Parts B and C is Tier 2. The MVP uses a passive Suricata sensor and the customer's existing firewall for enforcement (R4).

## **6\. Final System Architecture**

```
                         CUSTOMER ENVIRONMENT
 Internet --> [ SECURITY GATEWAY ]--> Internal network / apps / databases
                 | nftables + eBPF/XDP   | Suricata IDS/IPS | Zeek
                 | WAF / API proxy       | Data-access sensors (DB audit logs)
                 | Flow & feature extractor | Local policy cache (offline mode)
                 |
        mTLS, signed, compressed event stream (metadata, not raw content)
                 |
 =========================== CLOUD PLATFORM ===========================
  Ingestion API --> Event bus (Kafka/NATS) --> Stream processors
        |                                            |
        v                                            v
  Feature store  --> ML INFERENCE (6 core models + app/data models)
                       |
                       v
                MODEL FUSION + DISAGREEMENT ENGINE --> THREAT SCORE
                       |
                       v
         ASSET-AWARE RISK  <--  Knowledge graph + asset inventory
                       |
                       v
        AGENTIC INVESTIGATION (LangGraph, tools, RAG, threat intel)
                       |
                       v
        GAME-THEORETIC DECISION ENGINE (payoffs, Stackelberg/Bayesian)
                       |
                       v
        POLICY SAFETY GATE --(unsafe)--> reject / human approval
                       | (safe)
                       v
        RESPONSE ENGINE --> enforcement adapters --> gateway / WAF / IdP / DB
                       |
                       v
        VERIFICATION --> FEEDBACK --> retraining, tuning, reports
 ======================================================================
  Dashboard (React) | Incident timeline | Audit trail | Reports | APIs
```

## **7\. Component Inventory**

| **Component**            | **Responsibility**                                                                          | **Technology**                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Security gateway**     | Local firewall, IDS/IPS, WAF, traffic collection, local enforcement, offline policy         | Linux, nftables, eBPF/XDP, Suricata, Zeek, ModSecurity/Coraza              |
| **Gateway agent**        | Secure tunnel, config sync, event shipping, command execution through allowed adapters only | Go or Python service, mTLS, signed config                                  |
| **Ingestion service**    | Authenticates gateways, validates and normalizes events                                     | FastAPI, JSON Schema/Protobuf                                              |
| **Event bus**            | Decouples ingestion, ML, agents, response                                                   | Kafka, Redpanda, or NATS JetStream                                         |
| **Feature service**      | Computes flow, session and entity features                                                  | Python, Polars/Pandas, Redis feature cache                                 |
| **ML inference service** | Runs core and extension models                                                              | scikit-learn, XGBoost, LightGBM, PyTorch/ONNX Runtime                      |
| **Fusion and scoring**   | Combines model outputs, applies calibration and disagreement logic                          | Python service                                                             |
| **Knowledge graph**      | Relationships between IPs, devices, users, services, data stores, alerts, incidents         | Neo4j, or PostgreSQL with Apache AGE                                       |
| **Agent runtime**        | Investigation workflows, tools, memory, RAG                                                 | LangGraph, LangChain where useful, pgvector                                |
| **Game engine**          | Computes defender strategy from payoffs                                                     | NumPy, SciPy, cvxpy, nashpy, OpenSpiel (research)                          |
| **Safety gate**          | Validates every proposed action                                                             | Policy engine (custom rules + OPA/Rego)                                    |
| **Response engine**      | Executes approved actions through adapters; tracks TTL and rollback                         | Python workers, idempotent adapters                                        |
| **Verification service** | Checks effect of each action                                                                | Scheduled and event-driven checks                                          |
| **API and dashboard**    | Customer UI, admin, reports                                                                 | FastAPI, React, TypeScript, WebSocket                                      |
| **Datastores**           | Relational, cache, object, time series, vectors                                             | PostgreSQL, Redis, S3-compatible storage, TimescaleDB/ClickHouse, pgvector |
| **Observability**        | Metrics, logs, traces of the platform itself                                                | Prometheus, Grafana, OpenTelemetry, Loki                                   |

## **8\. Technology Stack and Reasons**

| **Area**                     | **Choice**                                        | **Why**                                                                   |
| ---------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------- |
| **Language (platform)**      | Python 3.11+                                      | Best ML ecosystem; fast to build; FastAPI is async and typed              |
| **Language (gateway agent)** | Go (or Rust) preferred; Python acceptable for MVP | Small static binary, low memory, easy to ship to customers                |
| **Packet processing**        | nftables + eBPF/XDP                               | Kernel-level speed for filtering and rate limiting; standard on Linux     |
| **IDS/IPS**                  | Suricata (+ Zeek for protocol logs)               | Mature, open source, rule ecosystems, JSON output (EVE)                   |
| **WAF**                      | ModSecurity or Coraza with OWASP Core Rule Set    | Widely used baseline rules for injection, XSS and more                    |
| **ML libraries**             | scikit-learn, XGBoost, LightGBM, PyTorch          | Tree ensembles are strong on tabular flow data; neural nets for sequences |
| **Model registry**           | MLflow                                            | Versioning, metrics, artifacts, staging/production stages                 |
| **Edge inference**           | ONNX Runtime                                      | Run trained models on small gateways without heavy runtime                |
| **Agents**                   | LangGraph                                         | Explicit state machine, retries, human-in-the-loop checkpoints            |
| **Vector search**            | pgvector                                          | One less system to run; sufficient for the knowledge base size            |
| **Policy engine**            | Open Policy Agent (Rego)                          | Declarative, testable safety rules                                        |
| **Frontend**                 | React + TypeScript + Vite + Tailwind              | Typed UI, fast development, large ecosystem                               |
| **Infrastructure**           | Docker, Kubernetes later, Terraform               | Reproducible environments; scale when needed                              |

## **9\. Event Pipeline and Normalized Event Schema**

Every sensor (firewall, IDS, WAF, database audit, identity logs) is converted into one normalized event format. The rest of the platform never needs to know which sensor produced an event.

```
{
  "event_id": "evt_01HZX...",
  "tenant_id": "t_123",
  "gateway_id": "gw_9",
  "timestamp": "2026-10-08T10:15:42.120Z",
  "layer": "network | application | data | identity",
  "source": {"ip": "203.0.113.7", "port": 51544, "asn": 64500, "geo": "XX"},
  "destination": {"ip": "10.0.5.20", "port": 443, "asset_id": "a_77"},
  "protocol": "TCP",
  "features": {"duration": 12.4, "fwd_pkts": 410, "bwd_pkts": 3, "syn_count": 400},
  "labels_from_sensors": ["ET SCAN Nmap"],
  "raw_ref": "s3://.../pcap-slice-42"      // pointer, not content
}
```

### **9.1 Topics / streams**

| **Topic**                                              | **Content**                                                       |
| ------------------------------------------------------ | ----------------------------------------------------------------- |
| **events.raw**                                         | Normalized events from gateways and connectors                    |
| **features.flow / features.session / features.entity** | Computed features per flow, per session and per user/device       |
| **detections.model**                                   | Per-model predictions with probability, confidence, model version |
| **threat.scores**                                      | Fused scores with category, severity, asset risk                  |
| **investigations.requests / results**                  | Agent tasks and structured findings                               |
| **decisions.proposed**                                 | Game-engine outputs (candidate actions with expected loss)        |
| **decisions.approved / decisions.rejected**            | Outputs of the safety gate                                        |
| **actions.executed**                                   | Enforcement results                                               |
| **verification.results**                               | Post-action checks                                                |
| **audit.log**                                          | Immutable record of every decision and change                     |

## **10\. Multi-Tenancy, Connectivity and Offline Operation**

- **Tenant isolation:** every row and every message carries tenant_id; PostgreSQL row-level security enforces it; separate encryption keys per tenant; optional dedicated database for enterprise tenants.
- **Gateway trust:** each gateway has a unique certificate (mTLS); enrolment uses a one-time token; certificates rotate automatically; revoked gateways are rejected immediately.
- **Signed configuration:** policy and model bundles pushed to gateways are signed; the gateway verifies the signature before applying them.
- **Offline mode:** if the cloud is unreachable, the gateway keeps enforcing the last known policy, applies local rate limits and rules, queues events on disk and replays them when the link returns. It never invents new blocking decisions without cloud analysis, except for a small set of pre-approved local protections (for example SYN-flood limits).
- **Data minimisation on the wire:** only features and metadata leave the customer network by default; raw packets stay local unless an incident requires evidence collection and the customer permits it.
- **Time synchronisation:** gateways use authenticated NTP so audit timestamps and correlation remain trustworthy.

# **PART C: LAYER 1, NETWORK SECURITY**

## **11\. Deterministic Network Controls**

These controls are the foundation and must be correct before any AI is added. The full control list (the detailed firewall checklist) covers 70+ areas; the essential ones are:

| **Control**             | **Implementation notes**                                                                                                                  |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Default deny**        | Inbound deny by default; explicit allow rules per service; outbound restricted by role (egress filtering)                                 |
| **Stateful inspection** | Connection tracking (conntrack) with per-source and per-destination limits, invalid-state drops, state-table protection                   |
| **Anti-spoofing**       | Reverse-path filtering, bogon and martian filtering, ingress and egress source validation                                                 |
| **Rate limiting**       | nftables meters/limits per source, per service and per user; SYN cookies; connection-rate limits                                          |
| **Protocol hygiene**    | TCP flag validation, fragment handling and reassembly limits, ICMP restrictions, malformed-header drops                                   |
| **Segmentation**        | VLANs/zones; east-west rules to limit lateral movement; protected zones for data stores and medical/OT devices                            |
| **IDS/IPS**             | Suricata with maintained rule sets; EVE JSON output feeds the event bus; IPS mode only after tuning                                       |
| **NAT / VPN**           | Documented NAT policy; VPN with strong crypto, MFA and per-user policy                                                                    |
| **DNS / TLS**           | DNS logging and filtering; TLS version and cipher policy; certificate validation for management services                                  |
| **Management plane**    | Admin access only from management network, MFA, no default credentials, signed updates, config validation and automatic rollback          |
| **Fail-safe design**    | On crash or overload, fail to a defined safe mode (usually keep existing allow rules, protect critical zones); watchdog and health checks |
| **High availability**   | Active/passive gateway pair with state sync (for example keepalived)                                                                      |

### **11.1 Policy lifecycle**

```
Draft policy -> Syntax and conflict validation -> Simulation on recorded traffic
   -> Staged rollout (monitor mode) -> Enforce -> Version stored -> One-click rollback
```

Policies are versioned, atomically applied (no half-applied rule sets), and checked for duplicate, shadowed, conflicting and unused rules before activation.

## **12\. Traffic Collection and Feature Extraction**

### **12.1 Collection sources**

- Flow records from the gateway (NetFlow/IPFIX style) and bidirectional flow features.
- Suricata EVE JSON (alerts, flow, DNS, TLS, HTTP metadata).
- Zeek logs (conn, dns, http, ssl, files, notice).
- Selective packet capture slices as evidence (not a continuous full capture).
- Interface counters and system metrics for the gateway itself.

### **12.2 Flow feature groups**

| **Group**             | **Examples**                                                                                                    |
| --------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Volume**            | Packets and bytes forward/backward, packets per second, bytes per second, mean/max/min/std of packet length     |
| **Timing**            | Flow duration, inter-arrival time statistics (forward, backward, flow), active/idle times                       |
| **TCP behaviour**     | SYN/FIN/RST/PSH/ACK/URG counts, window sizes, retransmissions, half-open ratio, handshake completion            |
| **Rate and ratio**    | Forward/backward ratio, new connections per second per source, unique destination ports per source              |
| **Fan-out / fan-in**  | Unique destinations contacted by a source, unique sources hitting a destination (scan and DDoS indicators)      |
| **Protocol metadata** | DNS query length, entropy, NXDOMAIN ratio; HTTP method mix; TLS version, cipher list, SNI, JA3/JA4 fingerprints |
| **Encrypted-traffic** | Packet size sequences, direction patterns, handshake fingerprints (works without decryption)                    |
| **Entity context**    | Historical baseline of the source/destination/user: usual hours, usual peers, usual volume                      |
| **Time window**       | Aggregates over 10 s, 1 min, 10 min windows to catch slow attacks                                               |

### **12.3 Pipeline rules**

- Features are computed identically for training and live inference (shared code in one library) to avoid training/serving skew.
- Missing or infinite values are handled by explicit rules, never silently.
- Private identifiers (IP addresses, user names) are pseudonymised before long-term storage where policy requires.
- Feature definitions are versioned; each model records which feature version it expects.

## **13\. Datasets for Model Development**

Public datasets are used to build and compare models, but they are never treated as proof of real-world performance. They are old, synthetic in places, and have well-known artefacts. Cross-dataset testing and live pilots are mandatory.

| **Dataset**                                                | **Content**                                                          | **Use and caution**                                                                                                   |
| ---------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **CIC-IDS2017 / CSE-CIC-IDS2018**                          | Flows with DoS, DDoS, brute force, web attacks, infiltration, botnet | General intrusion classification; check for labelling and duplicate issues                                            |
| **UNSW-NB15**                                              | Modern attack categories incl. fuzzers, exploits, reconnaissance     | Cross-dataset validation                                                                                              |
| **CIC-DDoS2019**                                           | Many DDoS variants (reflection, amplification, flood)                | DDoS model                                                                                                            |
| **NSL-KDD / KDD99**                                        | Classic benchmark                                                    | Baseline only; outdated and unrepresentative                                                                          |
| **CTU-13**                                                 | Botnet traffic captures                                              | Botnet/C2 behaviour                                                                                                   |
| **Bot-IoT / ToN-IoT / CIC-IoT**                            | IoT network and telemetry attacks                                    | IoT and OT scenarios                                                                                                  |
| **Web attack data (CSIC 2010, ModSecurity logs, own lab)** | HTTP requests normal vs malicious                                    | Application-layer models                                                                                              |
| **Own lab and pilot traffic**                              | Replayed attacks plus real benign traffic from consenting customers  | Most representative of real deployments; use only with written customer consent and inside the tenant-isolation rules |

**Rule:** a model is not accepted because it scored 99% on a public dataset. It is accepted when it keeps acceptable precision and recall on a different dataset, on replayed lab traffic, and in shadow mode on a real network.

# **PART D: MACHINE LEARNING LAYER**

## **14\. Model Catalogue**

Six core models cover the network layer. Three extension models cover application and data. Each model has one narrow job, so errors are easier to understand and fix. A routing step decides which models see which traffic, so not every model runs on every flow.

| **#**         | **Model**                    | **Detects**                                                             | **Candidate algorithms**                                                         | **Primary metrics**                                |
| ------------- | ---------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------- |
| **M1**        | Network anomaly              | Unknown or zero-day deviations from normal behaviour                    | Isolation Forest, autoencoder, one-class SVM, LSTM autoencoder                   | Recall on held-out attacks, false-positive rate    |
| **M2**        | Intrusion classifier         | Known attack classes (DoS, probe, brute force, web, infiltration)       | XGBoost, LightGBM, Random Forest, Extra Trees, MLP                               | Per-class precision/recall, macro-F1               |
| **M3**        | DDoS detector                | Volumetric, protocol and application floods; reflection/amplification   | LightGBM on window features + EWMA/CUSUM statistics + source/destination entropy | Detection latency, recall, FPR during flash crowds |
| **M4**        | Malicious traffic / C2       | Botnet beaconing, malware communication, DNS tunnelling, suspicious TLS | 1D-CNN/LSTM on packet sequences, GBDT on DNS/TLS features, periodicity analysis  | Precision at fixed recall, time to detect beacon   |
| **M5**        | User/device behaviour (UEBA) | Compromised accounts and devices, lateral movement, policy drift        | Per-entity baselines, peer-group Isolation Forest, sequence autoencoder          | Alert precision, analyst-confirmed rate            |
| **M6**        | Network risk prediction      | Probability that an entity will be involved in an incident soon         | Gradient boosting on exposure + history + vulnerability data                     | AUROC, AUPRC, calibration                          |
| **M7 (ext.)** | Web request anomaly          | Injection, XSS, path traversal, abnormal API use                        | Character n-gram classifier, autoencoder on request structure, small transformer | Precision at low FPR, per-OWASP category recall    |
| **M8 (ext.)** | Data-access anomaly          | Unusual queries, bulk reads, new access paths                           | Per-user/role baselines, Isolation Forest, sequence models on query fingerprints | Alert precision, rows-at-risk caught               |
| **M9 (ext.)** | Exfiltration detector        | Abnormal outbound volume, staging, covert channels                      | Gradient boosting on volume/destination/time features + DNS tunnelling features  | Recall, bytes-at-risk before containment           |

**Revision 2:** MVP models are M2 and M3 only, and only if they beat Suricata-only detection in the ablation. M1, M4 and M5 are Tier 2. M6 to M9 are Tier 3. M6 is never a detection vote (section 18).

## **15\. Model Details**

### **15.1 M1 Network anomaly detector**

- **Training data:** benign-only flows from the customer environment (after a learning period) plus public benign traffic.
- **Idea:** learn what normal looks like; score distance from normal. Autoencoder score = reconstruction error normalised to a 0-1 range using the benign validation distribution.
- **Strengths / limits:** can catch unseen attacks but produces more false positives; always combined with other models, never used alone to block.

### **15.2 M2 Intrusion classifier**

- **Training data:** labelled multi-class flows; class imbalance handled with class weights, focal loss or careful resampling applied only to the training split.
- **Output:** probability per class plus top class; unknown/low-confidence flows go to the disagreement engine.
- **Why trees:** gradient-boosted trees are usually strong and fast on tabular flow features and easy to explain with SHAP.

### **15.3 M3 DDoS detector**

- **Window features:** packets/s, new flows/s, unique sources, source-IP entropy, destination-port entropy, SYN/ACK ratio, request rate per URL.
- **Statistical layer:** EWMA/CUSUM change detection runs beside the ML model for fast, explainable alarms.
- **Flash-crowd awareness:** legitimate surges have diverse, behaving sources; features such as source diversity and handshake completion help avoid blocking real customers.

### **15.4 M4 Malicious traffic and C2 detector**

- **Beaconing:** measure periodicity and low jitter in connection times (autocorrelation or FFT on inter-arrival times).
- **DNS:** query-name length, character entropy, NXDOMAIN ratio, rare-domain age, TXT/NULL record use.
- **TLS metadata:** JA3/JA4 fingerprints, SNI, certificate features; no decryption required.
- **Threat intelligence join:** matches against IOC feeds raise the score but do not decide alone.

### **15.5 M5 User and device behaviour model**

- **Entities:** users, devices, service accounts, IoT devices.
- **Baseline:** typical hours, peers, ports, volumes, protocols; compared against a peer group (devices of the same type/role).
- **Lateral movement signals:** first-time internal connections, unusual admin protocols (SMB, RDP, SSH) between peers, rapid fan-out inside the network.

### **15.6 M6 Network risk prediction**

- Predicts risk per asset/entity for the next time window using exposure (open services, vulnerable software), recent alerts and history.
- Used for prioritisation and proactive hardening advice, not for direct blocking. In fusion (section 18) M6 is not a detection vote: it is excluded from the attack-score average and only supplies a prioritisation weight.

## **16\. Feature Engineering and Preprocessing**

- **Cleaning:** remove duplicate flows, handle NaN/Inf, fix known dataset artefacts, drop identifiers that leak labels (for example fixed IPs/timestamps used only by the attacker in a lab dataset).
- **Scaling:** standard or robust scaling for neural models; trees need none. Fit scalers on training data only.
- **Encoding:** protocol and flag fields one-hot or target-free encodings; high-cardinality fields hashed.
- **Imbalance:** class weights, balanced sampling, focal loss; resampling (for example SMOTE) only inside training folds.
- **Leakage control:** split by time or by capture session, not random rows, because neighbouring flows from one attack are near-duplicates.
- **Feature selection:** remove highly correlated features; use permutation importance and SHAP to drop features that only work on one dataset.
- **Window and sequence building:** consistent window sizes for streaming; sequence models use fixed-length padded windows with masks.

## **17\. Training and Evaluation Methodology**

### **17.1 Protocol**

```
1. Define task, label policy and acceptable operating point (FPR budget)
2. Split by time / session:  train | validation | test | external dataset
3. Train baseline (logistic regression / RF) then stronger models
4. Tune on validation (Optuna or grid), never on test
5. Calibrate probabilities (Platt scaling or isotonic regression)
6. Choose threshold at the required precision/recall trade-off
7. Test on held-out + EXTERNAL dataset + replayed lab attacks
8. Shadow mode on real traffic (no enforcement) and compare with analysts
9. Register model, data version, feature version, metrics, model card
```

### **17.2 Metrics**

| **Metric**                         | **Why it matters**                                                         |
| ---------------------------------- | -------------------------------------------------------------------------- |
| **Precision / Recall / F1**        | Basic trade-off; report per class, not only overall                        |
| **False-positive rate**            | Directly equals wrongly blocked or alerted legitimate traffic              |
| **AUROC and AUPRC**                | AUPRC is more honest when attacks are rare                                 |
| **MCC**                            | Single-number summary robust to imbalance                                  |
| **Calibration (Brier score, ECE)** | Probabilities feed fusion and game theory, so they must mean what they say |
| **Detection latency**              | Time from attack start to detection                                        |
| **Cross-dataset drop**             | Performance fall on a different dataset signals overfitting to artefacts   |
| **Inference latency and memory**   | Must fit gateway or cloud budgets                                          |

### **17.3 Explainability**

SHAP values or tree path explanations are stored with each high-severity detection, so analysts and agents can see which features drove the score.

## **18\. Model Fusion Theory**

The fusion layer turns several imperfect predictions into one threat score plus an uncertainty estimate. Several methods are implemented and compared; the choice is data-driven.

| **Method**                     | **Formula / idea**                                                                                        | **When useful**                                              |
| ------------------------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Simple average**             | S = (1/n) \* sum(p_i)                                                                                     | Baseline                                                     |
| **Weighted average**           | S = sum(w_i \* p_i) / sum(w_i); w_i from calibration quality, e.g. 1/Brier_i, or per-category reliability | Models of different quality                                  |
| **Log-odds (Bayesian) fusion** | logit(S) = logit(prior) + sum( w_i \* (logit(p_i) - logit(prior)) )                                       | Principled combination of roughly independent evidence       |
| **Stacking**                   | Meta-learner (logistic regression or small GBDT) trained on out-of-fold predictions                       | When enough labelled data exists                             |
| **Noisy-OR**                   | S = 1 - product(1 - p_i)                                                                                  | High-recall categories; can inflate scores, so use with care |
| **Dempster-Shafer**            | Combine belief masses; keeps an explicit 'unknown' mass                                                   | When models can say 'I don't know'                           |

**Worked example (illustrative arithmetic only)** using five detection-model outputs (M1 to M5): 0.91, 0.76, 0.95, 0.83, 0.89. Their mean is 4.34 / 5 = 0.868, so a simple-average threat score is about 0.87 (87/100). M6 is excluded because it estimates future exposure, not whether an attack is under way. This is a score, **not a calibrated probability of attack**. A high score becomes a probability only after each model is calibrated on held-out data and the fusion method is validated (see section 77.1).

### **18.1 Disagreement engine**

- Compute spread (standard deviation or entropy) across models and note which models are silent or contradictory.
- High score with high disagreement: send to agentic investigation with an 'uncertain' flag; avoid automatic strong action.
- All models agree and score is high: allow stronger response subject to the safety gate.
- One specialist model strongly fires on its own category (for example the DDoS model): trust the specialist for that category.

### **18.2 Threat score output (illustrative format)**

```
{ "threat_score": 91, "confidence": 0.94, "attack_probability": 0.93,
  "category": "DDoS", "severity": "CRITICAL",
  "model_votes": {"M1":0.91,"M2":0.76,"M3":0.95,"M4":0.83,"M5":0.89},
  "disagreement": 0.07, "explanation_refs": ["shap_8841"] }
```

## **19\. Asset-Aware Risk**

The same attack matters differently on different assets. The platform converts a threat score into risk using asset context.

```
Risk = P(attack) x Impact(asset) x Exposure(asset) x (1 - ControlEffectiveness)
```

```
Impact   : business criticality + data sensitivity (from data classification)
Exposure : internet-facing? known vulnerabilities (CVSS/EPSS, CISA KEV)?
Controls : is a patch/WAF/segmentation rule already reducing the risk?
```

| **Scenario**                               | **Risk band** | **Typical response tier**                                 |
| ------------------------------------------ | ------------- | --------------------------------------------------------- |
| **Attack score 70 on public test server**  | Medium        | Monitor or rate-limit                                     |
| **Attack score 70 on production database** | Critical      | Investigate immediately, strong containment with approval |
| **Attack score 90 on isolated lab host**   | Low-Medium    | Log and notify                                            |

## **20\. Adversarial ML and Model Security**

| **Threat**                     | **Example**                                           | **Defence**                                                                                                                      |
| ------------------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Evasion**                    | Attacker shapes traffic to look benign                | Ensemble diversity, constraint-aware features, adversarial training with protocol-valid perturbations, anomaly model as backstop |
| **Data poisoning**             | Malicious samples in customer-labelled data or feeds  | Data provenance, outlier filtering, human review of retraining sets, per-tenant training isolation                               |
| **Model extraction / probing** | Repeated queries to learn decision boundary           | No public inference endpoint, rate limits, noisy/rounded scores externally                                                       |
| **Model tampering**            | Replacing a model artifact                            | Signed models, hash verification at load, registry access control                                                                |
| **Drift**                      | Traffic patterns change over time                     | Drift monitors, scheduled re-evaluation, rapid rollback                                                                          |
| **Alert flooding**             | Attacker triggers many false alerts to blind analysts | Correlation, deduplication, budgets on automated actions                                                                         |

## **21\. MLOps and Model Lifecycle**

```
Experiment (MLflow) -> Register -> Staging -> SHADOW (no action) -> CANARY (small tenants)
   -> PRODUCTION -> Monitor (drift, precision, latency) -> Retrain or ROLLBACK
```

- **Versioning:** data, features, code, hyperparameters and model artifact stored together; every prediction records the model version.
- **Drift detection:** Population Stability Index, PSI = sum( (a_i - e_i) \* ln(a_i / e_i) ); values above about 0.25 usually trigger review. Kolmogorov-Smirnov tests on key features.
- **Retraining triggers:** scheduled, drift-based, or after enough analyst-confirmed feedback.
- **Model cards:** each model documents intended use, data, metrics, limitations and known failure modes.
- **Fallback:** if a model fails, is stale or times out, fusion ignores it and lowers confidence; if all models fail, the system falls back to deterministic controls only.

# **PART E: APPLICATION AND DATA SECURITY LAYERS**

**Tier 3 (research, not for sale):** Part E and sections 22 to 24 are kept as a design reference. They are outside the MVP and Tier 2 and may be built only after a paying customer requests them (R3).

## **22\. Application and API Security**

### **22.1 Components**

- **Reverse proxy / WAF:** ModSecurity or Coraza with the OWASP Core Rule Set, tuned per application; starts in detection-only mode.
- **API gateway inspection:** validate requests against OpenAPI schemas (methods, parameters, types, sizes); detect undocumented (shadow) endpoints.
- **Bot and credential-stuffing detection:** request rate, header and TLS fingerprints, failed-login patterns across accounts, impossible travel.
- **Session and identity signals:** token reuse, session anomalies, privilege changes (from IdP logs).

### **22.2 Coverage map**

| **Risk (OWASP)**                                | **Signals**                                                      | **Response options**                                     |
| ----------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------- |
| **Injection (SQL, command, template)**          | Pattern + M7 request anomaly, parameter structure change         | Block request, WAF virtual patch, alert developers       |
| **Broken access control / BOLA (API1)**         | One session iterating object IDs, access across tenants/users    | Rate-limit, challenge, revoke session, alert             |
| **Broken authentication / credential stuffing** | Many failed logins across accounts, shared IPs, bot fingerprints | Rate-limit, CAPTCHA/challenge, MFA step-up, block source |
| **Unrestricted resource consumption (API4)**    | High request cost, large payloads, rapid sequences               | Quota enforcement, throttling                            |
| **SSRF**                                        | Requests causing internal metadata or internal address access    | Block egress to internal/metadata ranges, alert          |
| **Security misconfiguration**                   | Missing headers, verbose errors, exposed admin paths             | Posture report, WAF rule                                 |
| **Vulnerable components**                       | Software inventory matched to CVE/KEV/EPSS                       | Prioritised patch list, temporary WAF rule               |
| **Sensitive business flow abuse (API6)**        | Scripted purchases, scraping, enumeration                        | Bot challenge, per-account limits                        |

OWASP Top 10 and OWASP API Security Top 10 are used as the reference taxonomy for coverage and for the test plan.

## **23\. Data Security Layer**

### **23.1 Data discovery and classification**

- **Where:** connect read-only to databases, object storage and file shares; sample and classify column/object metadata rather than copying content out.
- **How:** pattern detectors with checksum validation (for example Luhn for payment cards; Verhoeff for Aadhaar numbers; format rules for PAN, IFSC, phone, email, passport), named-entity recognition (spaCy, Microsoft Presidio) for names and addresses, column-name heuristics, and optional small ML classifiers.
- **Labels:** Public, Internal, Confidential, Restricted; plus type tags (payment card, government ID, health record, credentials).
- **Output:** a data map linking each store to sensitivity and owner; this feeds asset-aware risk and the knowledge graph.
- **Privacy:** classification runs inside the customer environment where required; only labels and counts leave.

### **23.2 Data-access monitoring (UEBA)**

- **Sources:** PostgreSQL pgaudit, MySQL/MariaDB audit plugins, SQL Server audit, MongoDB audit logs, cloud audit logs (for example CloudTrail data events, storage access logs), application query logs.
- **Features:** user/role, query fingerprint, tables and sensitivity touched, rows returned, time of day, client IP/app, failed attempts, new access paths.
- **Detections:** bulk read of Restricted data, first-time access to a sensitive table, service account used interactively, privilege escalation, access from unusual network location.

### **23.3 Exfiltration detection**

- Unusual outbound volume per host/user compared with baseline; uploads to unknown cloud storage or paste sites.
- Staging behaviour: many reads then archive creation then outbound transfer.
- Covert channels: DNS tunnelling (long, high-entropy labels, high query volume to one domain), ICMP or unusual protocol tunnelling.
- Correlation with network (M2-M4) and application events to reconstruct the full path from compromise to data movement.

### **23.4 Exposure and protection posture**

- Publicly exposed databases or storage buckets; databases reachable from the internet.
- Unencrypted data at rest or in transit; weak TLS; missing key rotation.
- Default or shared credentials; excessive privileges; stale accounts.
- Backup presence and restore-test status (ransomware resilience).
- Recommendations include masking, tokenisation and field-level encryption for Restricted data.

### **23.5 Data-layer response actions**

| **Action**                 | **Effect**                                                                                |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| **Raise inspection**       | Log full query/transfer metadata for the entity                                           |
| **Throttle transfer**      | Limit outbound bandwidth for the host or session                                          |
| **Revoke session / token** | Force re-authentication through the identity provider                                     |
| **Restrict database role** | Temporarily remove access to Restricted tables (reversible)                               |
| **Block destination**      | Block outbound to the suspicious address/domain                                           |
| **Quarantine workload**    | Isolate the host or container from the data zone (approval required for critical systems) |

## **24\. Security Knowledge Graph**

The graph lets agents reason about relationships instead of isolated alerts.

```
Nodes: IP, Device, User, Service, Port, Application, API Endpoint, Database,
       DataStore, DataClass, Vulnerability, Alert, Attack, Incident, Asset, Action
Edges: (IP)-[CONNECTED_TO]->(Service)   (User)-[LOGGED_INTO]->(Device)
       (Service)-[HAS_VULN]->(Vulnerability)   (Database)-[CONTAINS]->(DataClass)
       (Alert)-[PART_OF]->(Incident)   (Action)-[APPLIED_TO]->(IP|User|Device)
```

Example question the graph answers quickly: "Which sensitive data stores can be reached from the device that just beaconed?" (path query from the compromised device through allowed network paths to databases tagged Restricted). The result raises the incident severity and guides containment.

# **PART F: AGENTIC SECURITY LAYER**

## **25\. Agentic Architecture**

After detection, the system does not block immediately. A set of specialised agents investigates the event. They are implemented as a LangGraph state machine: each node is an agent or tool step, the shared state holds the evidence, and checkpoints allow retries and human review.

```
Trigger (threat score above investigation threshold)
   -> Triage node (is this already part of an open incident?)
   -> Traffic Analysis Agent      -> Threat Intelligence Agent
   -> Application/Data Context Agent -> Threat Investigation Agent (correlation)
   -> Evidence Agent (collect & preserve)
   -> Incident Response Agent (recommend actions)
   -> Policy Agent (check constraints) -> output: structured Investigation Report
   -> hand-off to Game-Theoretic Decision Engine
```

| **Agent**                      | **Job**                                                                                       | **Typical tools (read-only)**                  |
| ------------------------------ | --------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Triage**                     | Deduplicate; attach event to an open incident or start a new one                              | Incident store, alert store                    |
| **Traffic Analysis**           | Explain the traffic pattern, find related flows and affected ports                            | Flow search, Zeek/Suricata logs, feature store |
| **Threat Intelligence**        | Check IPs, domains, hashes, JA3 against feeds; map to MITRE ATT&CK                            | IOC lookup, ATT&CK knowledge base              |
| **Application / Data Context** | Identify which application, API or data store is involved and its sensitivity                 | Asset inventory, data map, WAF logs, DB audit  |
| **Threat Investigation**       | Correlate alerts, reconstruct the attack sequence, assess campaign, severity and attack paths | Knowledge graph queries, timeline builder      |
| **Evidence**                   | Preserve logs, packet slices and model explanations with hashes                               | Evidence store, hashing                        |
| **Incident Response**          | Propose response options with expected effect and side effects                                | Playbook library, asset criticality            |
| **Policy**                     | Check proposals against customer policy and protected-asset lists                             | Policy store (OPA queries)                     |
| **Verification**               | After action, test whether the attack stopped and nothing broke                               | Metrics, probes, flow checks                   |

## **26\. Tools and Permission Model for Agents**

| **Tool group**                                | **Read** | **Propose**                | **Execute**                                         |
| --------------------------------------------- | -------- | -------------------------- | --------------------------------------------------- |
| **Search logs, flows, alerts**                | Yes      | n/a                        | No                                                  |
| **Query knowledge graph and asset inventory** | Yes      | n/a                        | No                                                  |
| **Threat intelligence lookups**               | Yes      | n/a                        | No                                                  |
| **Create incident, notes, tickets**           | Yes      | Yes                        | Yes (non-security-changing)                         |
| **Create firewall/WAF/IdP/database action**   | No       | Yes (as a proposal object) | No (only the Response Engine after the safety gate) |
| **Change policy, models, tenant settings**    | No       | No                         | No                                                  |

**Rule:** agents can read and propose; only the Response Engine, after the Safety Gate, can change enforcement. No agent has a tool that talks directly to the firewall.

## **27\. Knowledge Base and RAG**

- **Sources:** MITRE ATT&CK, CVE/NVD, CISA Known Exploited Vulnerabilities, EPSS scores, OWASP Top 10 and API Top 10, vendor advisories, internal runbooks, past incident reports (per tenant).
- **Ingestion:** scheduled crawlers/importers; documents chunked (about 500-800 tokens with overlap) and embedded; stored in PostgreSQL with pgvector alongside metadata (source, date, tenant).
- **Retrieval:** hybrid (keyword + vector) with re-ranking; agents must cite retrieved items in their reports.
- **Freshness:** vulnerability and threat data refreshed frequently; stale items flagged.
- **Tenant separation:** customer-specific runbooks and incidents are never mixed across tenants.

## **28\. LLM Provider Abstraction**

The agent layer must not depend on one model vendor. All LLM access goes through a provider interface.

```
LLMProvider
  generate(prompt, schema)   classify(text, labels)   extract(text, json_schema)
      |                |                |
 OllamaProvider   HostedAPIProvider   FutureProvider
 (local models)   (commercial API)    (self-hosted / other)
# .env (backend only; never in frontend)
LLM_PROVIDER=ollama            # or: hosted
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=<local model>
HOSTED_API_KEY=<secret>
HOSTED_MODEL=<model name>
EMBEDDING_MODEL=<embedding model>
```

- Changing LLM_PROVIDER switches the model without code changes.
- Small tasks (classification, extraction) use small/local models; complex reasoning uses a stronger model.
- Every call records provider, model, prompt version, input hash, output and latency for audit.
- Customers with strict privacy can run local models only.

## **29\. Prompt Injection and LLM Safety**

Security data is hostile by nature. A log line, HTTP header or domain name can contain text such as "ignore previous instructions". The design assumes this will happen.

- Untrusted content is passed as quoted data fields, never merged into instructions.
- Agents return **structured JSON** validated against a schema; free text is never executed.
- Tool allowlists per agent; no tool can change enforcement (section 26).
- No secrets, keys or other tenants' data in the context.
- Output validation: IP/CIDR formats, action names from an enum, asset IDs that exist.
- High-impact proposals always pass the safety gate and may require human approval.
- A red-team test set of injection attempts runs in CI against every prompt change.

## **30\. Agent Memory, Orchestration and Evaluation**

- **Short-term memory:** the incident state object (evidence, hypotheses, tool results).
- **Long-term memory:** closed incidents and analyst feedback stored in the database and retrievable via RAG.
- **Orchestration:** timeouts per step, bounded retries, maximum tool-call budget per incident; on failure the incident escalates to a human with partial evidence.
- **Evaluation set:** a golden set of recorded incidents with known answers.
- **Agent metrics:** investigation accuracy, correct ATT&CK mapping, hallucinated-fact rate, tool-call correctness, unsafe-proposal rate, average time to report.

# **PART G: GAME-THEORETIC DECISION LAYER**

**Tier 3 (research, not for sale):** the MVP uses the deterministic response ladder of section 36 and the safety gate of section 37. The payoff parameters in section 33 are estimates, and the safety gate already limits automatic action by score and level, so the optimiser's choice set is small. The engine may be built as a research comparison against the ladder and enters the product only if that comparison shows a measurable benefit on pilot data.

## **31\. Theory Foundations**

Cyber defence is adversarial: the attacker observes, adapts and chooses actions in response to defences. Game theory gives mathematical tools for choosing a response when an intelligent opponent is involved. The platform uses a layered approach: simple decision theory first, richer game models where they add value.

| **Concept**                             | **Meaning**                                                 | **Use in the platform**                                                    |
| --------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Normal-form game**                    | Players, action sets and payoff matrix; simultaneous choice | Basic model of attacker vs defender actions                                |
| **Nash equilibrium**                    | No player gains by changing strategy alone                  | Reference solution for response mixing                                     |
| **Mixed strategy**                      | Choose actions with probabilities                           | Unpredictable defence (rotating inspection, random audits)                 |
| **Zero-sum / minimax**                  | One player's gain is the other's loss                       | Worst-case defence when attacker payoff is unknown                         |
| **Stackelberg security game**           | Defender commits first; attacker observes and best-responds | Main model: defenders publish consistent policies; attacker adapts to them |
| **Bayesian game**                       | Players have private types with a probability distribution  | Attacker types: scanner, botnet, insider, targeted attacker                |
| **Repeated / stochastic (Markov) game** | Interaction over many rounds with state                     | Attacker pivots (new IP/port); defender adapts over time                   |
| **POMDP**                               | Decision-making with hidden state                           | Uncertainty about whether a host is really compromised                     |
| **Signalling and deception games**      | Defender sends deceptive signals                            | Honeypots, decoy services, honey tokens                                    |

## **32\. Attacker and Defender Strategy Sets**

| **Attacker strategies**                                | **Defender strategies**                   |
| ------------------------------------------------------ | ----------------------------------------- |
| **Continue current attack**                            | Allow                                     |
| **Change source IP**                                   | Monitor                                   |
| **Change port or protocol**                            | Increase inspection                       |
| **Increase intensity**                                 | Rate-limit                                |
| **Move laterally**                                     | Challenge (CAPTCHA, MFA step-up)          |
| **Try another vector (web, credentials, data access)** | Block connection / source                 |
| **Stop and wait (low and slow)**                       | Terminate session / revoke token          |
| **Exfiltrate data**                                    | Quarantine / isolate segment              |
|                                                        | Redirect to honeypot / activate deception |

## **33\. Payoff and Loss Model**

The baseline decision rule is expected-loss minimisation. For each candidate defender action a:

```
L(a) = P_attack x Damage x (1 - Eff(a))  +  Cost(a)  +  (1 - P_attack) x Disruption(a)
```

```
P_attack   : calibrated fused threat probability
Damage     : asset impact (business value + data sensitivity)
Eff(a)     : estimated effectiveness of action a (0..1)
Cost(a)    : operational cost of the action
Disruption : harm to legitimate users if the traffic was actually benign
Choose a* = argmin L(a)   (subject to the safety gate)
```

**Illustrative example** (assumed numbers): P_attack = 0.90, Damage = 100.

| **Action**            | **Eff** | **Cost** | **Disruption** | **Expected loss L(a)**  |
| --------------------- | ------- | -------- | -------------- | ----------------------- |
| **Allow**             | 0.00    | 0        | 0              | 0.9 x 100 x 1.00 = 90.0 |
| **Rate-limit**        | 0.40    | 2        | 5              | 54.0 + 2 + 0.5 = 56.5   |
| **Block source**      | 0.80    | 5        | 20             | 18.0 + 5 + 2.0 = 25.0   |
| **Quarantine device** | 0.95    | 15       | 60             | 4.5 + 15 + 6.0 = 25.5   |

Block source has the lowest loss, with quarantine close behind. The choice is passed to the safety gate; if the source is a protected address the gate rejects it and the next best action is used. Effectiveness and cost values are estimated from playbooks, simulation and pilot data and are updated by the verification feedback loop.

### **33.1 Worked 2x2 game (mixed strategy)**

Payoff to the defender (higher is better, zero-sum for simplicity). Attacker chooses Continue (A1) or Change vector (A2); defender chooses Block source (D1) or Increase inspection (D2).

|                             | **A1: Continue** | **A2: Change vector** |
| --------------------------- | ---------------- | --------------------- |
| **D1: Block source**        | 9                | 2                     |
| **D2: Increase inspection** | 4                | 7                     |

```
Let defender play D1 with probability p.
  Payoff vs A1 = 9p + 4(1-p) = 4 + 5p
  Payoff vs A2 = 2p + 7(1-p) = 7 - 5p
Equalise:  4 + 5p = 7 - 5p  ->  p = 0.3
Game value = 4 + 5(0.3) = 5.5
```

```
Attacker plays A1 with probability q:
  vs D1: 9q + 2(1-q) = 2 + 7q ;  vs D2: 4q + 7(1-q) = 7 - 3q
  Equalise: 2 + 7q = 7 - 3q -> q = 0.5 ; value = 5.5
Equilibrium: defender Block 30% / Inspect 70%; attacker Continue 50% / Change 50%
```

Meaning: against an adaptive attacker, a purely predictable defence is exploitable; mixing protections gives a guaranteed minimum payoff. In practice the platform applies mixing mainly to monitoring depth, challenges and deception, where randomisation is cheap and safe, rather than to hard blocks on production traffic.

## **34\. Stackelberg and Bayesian Models**

- **Stackelberg model:** the defender commits to a (possibly mixed) policy x; the attacker observes or learns it and best-responds. The defender chooses x to maximise its own utility given the attacker's best response (Strong Stackelberg Equilibrium, ties broken in the defender's favour).

**Revision 2 rule:** mixed strategies must not randomise enforcement. A mixed policy computed here may order monitoring or inspection effort only. A block, quarantine or isolation is always chosen deterministically from the response ladder and the safety gate.

- **Solving:** for each possible attacker response solve a linear program (multiple-LP approach); for many types use mixed-integer formulations such as DOBSS; approximate methods for larger problems.
- **Bayesian extension:** attacker types (automated scanner, botnet, criminal, insider, targeted attacker) with prior probabilities updated by observed behaviour (Bayes rule). The defence is optimised against the mixture of types.
- **Sequential extension:** a Markov game over states (clean, probed, exploited, lateral movement, exfiltration) with discount factor; solved approximately by value iteration or reinforcement learning in simulation.
- **Deception:** honeypots and decoy credentials modelled as signalling; the defender benefits when the attacker cannot tell real from fake.

## **35\. Implementing the Game Engine**

| **Item**                 | **Implementation**                                                                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Libraries**            | NumPy and SciPy (linprog) for LPs; cvxpy for convex formulations; nashpy for small matrix games; OpenSpiel and Gambit for research and verification                                        |
| **Inputs**               | Calibrated threat probability, category, asset impact, exposure, candidate actions with cost/effectiveness/disruption, attacker-type posterior, history of previous actions on this entity |
| **Outputs**              | Ranked actions with expected loss, chosen mixed strategy (if applicable), reasoning summary, confidence                                                                                    |
| **Parameter estimation** | Initial values from expert playbooks; refined by verification outcomes (did the action work?) and by simulation                                                                            |
| **Simulation**           | Microsoft CyberBattleSim, CybORG, NASim and a custom replay simulator to test strategies safely before they are used on customers                                                          |
| **Fallback**             | If the solver fails, times out or inputs are missing, use the deterministic response ladder (section 36)                                                                                   |
| **Explainability**       | Store payoff table, selected action, runner-up and the reason for the choice in the audit record                                                                                           |
| **Guards**               | Hard constraints (protected assets, maximum action level for the threat score) are applied by the safety gate, not by the solver                                                           |

Game theory here is a decision-support optimiser. Its parameters are estimates, so results are presented to customers as expected-loss comparisons with the assumptions visible, not as proofs of optimality.

## **36\. Response Ladder and Action Catalogue**

| **Level** | **Risk**  | **Typical actions**                                                    | **Approval**                                        |
| --------- | --------- | ---------------------------------------------------------------------- | --------------------------------------------------- |
| **L0**    | Info      | Log, tag, baseline update                                              | None                                                |
| **L1**    | Low       | Monitor, increase visibility, enrich                                   | None                                                |
| **L2**    | Medium    | Rate-limit, challenge, increase inspection, WAF stricter mode          | Auto if reversible and within budget                |
| **L3**    | High      | Block connection or source (with TTL), terminate session, revoke token | Auto for non-critical assets; approval for critical |
| **L4**    | Critical  | Quarantine device, restrict database role, block outbound destination  | Human approval (default)                            |
| **L5**    | Severe    | Isolate network segment, activate incident response, notify management | Human approval required                             |
| **L6**    | Emergency | Customer-defined emergency playbooks only                              | Human approval and logged confirmation              |

# **PART H: SAFETY, RESPONSE AND VERIFICATION**

## **37\. Policy Safety Gate**

Every proposed action passes the gate. The gate is deterministic code and policy (Open Policy Agent rules), not an AI model, so it can be tested exhaustively.

```
Proposed Action
   -> Schema check (valid action type, target format, TTL present)
   -> Permission check (is automation allowed for this tenant, asset, level?)
   -> Protected-asset check (never-block list: management, DNS, gateways, payment, life-critical devices)
   -> Conflict check (contradicts existing policy or a recent opposite action?)
   -> Blast-radius check (how many users/services/assets would be affected?)
   -> Availability check (would this break a critical service or the only path?)
   -> Reversibility check (can it be undone? is rollback tested?)
   -> Rate-of-change check (maximum automated actions per hour/day)
   -> Confidence check (score and agreement high enough for this level?)
   -> Approval routing (auto / human approval / reject)
   -> Safety Gate decision -> Response Engine
```

| **Check**               | **Examples of rules**                                                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Protected assets**    | Reject any block of the gateway, DNS servers, identity provider, payment gateway, or a customer-defined list                    |
| **Blast radius**        | Reject blocking a /16 or any rule matching more than N active users; require approval above a threshold                         |
| **Rate-of-change**      | No more than N new automatic blocks per 10 minutes without approval (stops runaway automation or attacker-induced block floods) |
| **Time-to-live**        | All blocks and rate limits expire by default; renewals require fresh evidence                                                   |
| **Confidence**          | L3 needs score >= configured threshold and low model disagreement; L4+ needs human approval                                     |
| **Maintenance windows** | Respect customer change freezes and maintenance schedules                                                                       |
| **Four-eyes**           | Critical-risk changes can require two approvers                                                                                 |

```
def safety_gate(action, ctx):
    checks = [schema, permission, protected_assets, conflicts, blast_radius,
              availability, reversibility, rate_of_change, confidence]
    results = [c(action, ctx) for c in checks]          # each returns pass/fail + reason
    if any(r.hard_fail for r in results):  return Decision("REJECT", results)
    if needs_human(action, results):       return Decision("REQUIRE_APPROVAL", results)
    return Decision("APPROVE", results)
```

## **38\. Response Engine and Enforcement Adapters**

| **Adapter**                                                                  | **Actions**                                                                | **Notes**                                                   |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Gateway firewall (nftables/eBPF)**                                         | Block/limit IP, port, session; set TTL; quarantine VLAN                    | Signed command; atomic ruleset update; local rollback timer |
| **WAF / API proxy**                                                          | Virtual patch rule, block request pattern, rate limit by key/IP, challenge | Rule versioning; detection-only mode first                  |
| **Identity provider (Keycloak, Microsoft Entra ID, Okta, Google Workspace)** | Revoke session/token, force re-authentication, disable account             | Needs scoped service account                                |
| **Database / data store**                                                    | Restrict role, disable service account, revoke storage token               | Reversible; approval for production                         |
| **Cloud (AWS, Azure, GCP)**                                                  | Modify security group/NSG, isolate instance, revoke key                    | Least-privilege cloud role                                  |
| **Notification / ticketing**                                                 | Slack, Microsoft Teams, email, SMS/WhatsApp, Jira/ServiceNow               | Non-enforcement actions                                     |

- **Idempotent:** repeating an action has no extra effect; every action has a unique ID.
- **Authenticated, authorised, logged and auditable:** each adapter call is signed and recorded.
- **Time-limited and reversible:** each action stores its undo procedure.
- **Dry-run mode:** every adapter can simulate and report what would change.
- **Failure handling:** if enforcement fails, retry with backoff, then alert and escalate; never leave half-applied changes.

## **39\. Continuous Verification**

After each action, the verification service answers a fixed set of questions:

| **Question**                                              | **Method**                                                                                               |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Did the attack stop?**                                  | Compare flow/request rates and detections before and after; check that blocked flows no longer succeed   |
| **Did the attacker change IP, port, protocol or vector?** | Look for similar behaviour from new sources (clustering by fingerprint, JA3, user-agent, target pattern) |
| **Is the affected device still compromised?**             | Check beaconing, new outbound connections, privilege changes, behaviour-model score                      |
| **Did legitimate traffic remain available?**              | Synthetic probes, user error rates, latency and success rates for protected services                     |
| **Did the action create unintended effects?**             | Dependency checks, customer-reported issues, rule hit counts on legitimate sources                       |
| **Is the situation stable?**                              | Observe over a window (for example 15 minutes, 1 hour, 24 hours) before closing                          |

```
Detect -> Investigate -> Decide -> Respond -> Verify -> Observe
                          ^                                |
                          +---- escalate / adjust action <-+  (if not contained)
```

Outcomes: **contained** (close incident, keep monitoring), **partially contained** (adjust response), **failed** (escalate to next level or human), **harmful** (roll back and notify immediately).

## **40\. Explainability and Audit Trail**

```
{
  "decision_id": "dec_5521", "incident_id": "inc_88", "timestamp": "...",
  "inputs": {"threat_score": 91, "category": "DDoS", "asset": "a_77 (critical)"},
  "model_versions": {"M2":"2.4.1","M3":"1.9.0"},
  "agent_report_ref": "rep_341",
  "game_engine": {"candidates":[{"action":"BLOCK_SOURCE","loss":25.0},{"action":"RATE_LIMIT","loss":56.5}],
                   "selected":"BLOCK_SOURCE"},
  "safety_gate": {"decision":"APPROVE","checks":{"protected":"pass","blast_radius":"pass"}},
  "approvals": [], "executed": {"adapter":"gateway","ttl":"30m","rollback_ref":"rb_20"},
  "verification": {"status":"contained","checked_at":"..."}
}
```

- The audit log is append-only, hash-chained and exportable for auditors.
- The dashboard shows a plain-language incident timeline: what happened, what the system did, why, and what the result was.

## **41\. Feedback and False-Positive Management**

- Analysts can mark an alert as true positive, false positive, or needs tuning; labels feed retraining.
- Allow-lists and suppression rules are scoped, time-limited and audited.
- A weekly false-positive review ranks the noisiest rules/models so they can be tuned first.
- Customer-reported disruptions automatically trigger a review of the action that caused them.

# **PART I: PRODUCT, APIS AND DATA MODEL**

## **42\. Platform API Catalogue**

All APIs live under /api/v1, use JSON, are authenticated, rate-limited, versioned and documented with OpenAPI.

| **Group**                 | **Endpoints**                                                                                                             | **Access**             |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| **Auth**                  | POST /auth/login, POST /auth/refresh, POST /auth/logout, GET /auth/me, POST /auth/mfa/verify                              | Public / user          |
| **Gateways**              | POST /gateways/enroll, GET /gateways, GET /gateways/{id}, POST /gateways/{id}/config, POST /gateways/{id}/revoke          | Admin / gateway (mTLS) |
| **Ingestion**             | POST /ingest/events (batched), POST /ingest/heartbeat                                                                     | Gateway (mTLS)         |
| **Events and flows**      | GET /events, GET /events/{id}, GET /flows, GET /flows/{id}                                                                | User                   |
| **Detections**            | GET /detections, GET /detections/{id}, GET /models, GET /models/{id}/metrics                                              | User / admin           |
| **Incidents**             | GET /incidents, GET /incidents/{id}, GET /incidents/{id}/timeline, POST /incidents/{id}/notes, POST /incidents/{id}/close | User                   |
| **Investigations**        | GET /investigations/{id}, POST /investigations/{id}/rerun                                                                 | Analyst                |
| **Decisions and actions** | GET /decisions, GET /decisions/{id}, POST /actions/{id}/approve, POST /actions/{id}/reject, POST /actions/{id}/rollback   | Approver               |
| **Policies**              | GET/POST/PUT/DELETE /policies, POST /policies/{id}/simulate, POST /policies/{id}/activate                                 | Admin                  |
| **Assets and data map**   | GET/POST/PUT /assets, GET /datastores, GET /datastores/{id}/classification, POST /discovery/scan                          | Admin                  |
| **Threat intelligence**   | GET /intel/indicators, POST /intel/feeds, GET /intel/lookup?value=                                                        | Analyst / admin        |
| **Knowledge graph**       | POST /graph/query (restricted), GET /graph/entity/{id}                                                                    | Analyst                |
| **Reports**               | GET /reports, POST /reports/generate, GET /reports/{id}/download                                                          | User                   |
| **Admin**                 | Users, roles, tenants, API keys, notification channels, audit-log export                                                  | Admin                  |
| **Realtime**              | WebSocket /ws/alerts, /ws/incidents                                                                                       | User                   |

```
Success: {"success": true, "data": {...}, "pagination": {"page":1,"limit":20,"total":100}}
Error:   {"success": false, "error": {"code":"FORBIDDEN","message":"..."}}
```

## **43\. Core Database Tables**

| **Group**              | **Tables**                                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------------------- |
| **Tenancy and access** | tenants, users, roles, permissions, api_keys, sessions, mfa_factors                                     |
| **Gateways**           | gateways, gateway_certs, gateway_configs, heartbeats                                                    |
| **Assets and data**    | assets, asset_groups, services, datastores, data_classes, data_findings, vulnerabilities                |
| **Events**             | events (partitioned by time), flows, web_requests, data_access_events, identity_events                  |
| **Detections**         | model_registry, model_predictions, threat_scores, feature_versions                                      |
| **Incidents**          | incidents, incident_events, investigations, agent_runs, evidence, notes                                 |
| **Decisions**          | decisions, proposed_actions, safety_gate_results, approvals, executed_actions, rollbacks, verifications |
| **Policy**             | policies, policy_versions, allow_lists, protected_assets, maintenance_windows                           |
| **Intelligence**       | ioc_indicators, feeds, kb_documents, kb_chunks (pgvector), attack_techniques                            |
| **Operations**         | audit_log (append-only), notifications, reports, feedback_labels, tenant_settings                       |

Large time-series tables (events, flows, predictions) use time partitioning and retention rules; TimescaleDB or ClickHouse can hold analytics data while PostgreSQL stays the source of truth for configuration and incidents.

## **44\. Dashboard and User Experience**

| **Screen**                   | **Content**                                                                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Overview**                 | Security posture score, active incidents, threats blocked, mean time to detect/contain, protected assets, gateway health              |
| **Live threat map and feed** | Real-time alerts by layer (network, application, data), severity filters                                                              |
| **Incident detail**          | Timeline, evidence, model votes, agent findings, chosen response with reasoning, verification status, approve/reject/rollback buttons |
| **Approvals inbox**          | Pending high-impact actions with expected effect and blast radius                                                                     |
| **Assets and data map**      | Assets, owners, criticality, data sensitivity, exposure, vulnerabilities                                                              |
| **Policy centre**            | Firewall/WAF/automation policies, simulation results, version history, rollback                                                       |
| **Threat intelligence**      | Feeds, matched indicators, ATT&CK heat-map                                                                                            |
| **Models and quality**       | Model versions, drift, precision/FPR trends, shadow-mode results                                                                      |
| **Reports**                  | Executive summary, compliance and audit reports, incident reports                                                                     |
| **Settings**                 | Users and roles, integrations, notification channels, automation level (monitor / recommend / autonomous)                             |

The **automation level** control is central to trust: customers start in Monitor, move to Recommend, and enable Autonomous per category and per asset group when they are comfortable.

## **45\. Gateway Agent Specification**

- **Footprint targets:** small CPU and memory budget; configurable limits so the gateway never starves production traffic (targets are validated in performance tests).
- **Functions:** enrol, authenticate, receive signed config/model bundles, collect and compress events, enforce local policy, execute allowed commands, report health.
- **Local safety:** local watchdog; automatic rollback if a new rule set breaks connectivity (for example, revert if the management channel is lost within a set time).
- **Updates:** signed, staged, with automatic rollback; no inbound management ports.
- **Hardening:** minimal OS, read-only root where possible, disk encryption, secure boot where available.

## **46\. External Integrations and APIs**

| **Integration**                                  | **Purpose**                            | **Access**         | **Notes**                         |
| ------------------------------------------------ | -------------------------------------- | ------------------ | --------------------------------- |
| **AbuseIPDB**                                    | IP reputation                          | API key            | Rate-limited tiers                |
| **AlienVault OTX**                               | Pulses and IOCs                        | API key            | Free tier available               |
| **MISP**                                         | Threat-sharing platform                | API key            | Self-hosted or community          |
| **VirusTotal**                                   | File/URL/IP reputation                 | API key            | Quota limits                      |
| **abuse.ch (URLhaus, ThreatFox, Feodo Tracker)** | Malware URL, IOC and botnet C2 feeds   | Public / key       | Good free sources                 |
| **Spamhaus**                                     | IP/domain blocklists                   | Licence            | Check commercial terms            |
| **NVD / CVE API**                                | Vulnerability data                     | API key (optional) | Rate-limited                      |
| **CISA KEV catalogue**                           | Known exploited vulnerabilities        | Public JSON        | Strong prioritisation signal      |
| **FIRST EPSS**                                   | Exploit prediction scores              | Public API         | Prioritisation                    |
| **MITRE ATT&CK (STIX/TAXII)**                    | Technique mapping                      | Public             | Knowledge base source             |
| **Wazuh / Elastic / Splunk**                     | Log and SIEM exchange                  | API                | Customer SIEM integration         |
| **Identity providers**                           | Session revoke, user context           | OIDC/SCIM/API      | Keycloak, Entra ID, Okta, Google  |
| **Cloud APIs**                                   | Asset inventory, audit logs, isolation | IAM roles          | AWS, Azure, GCP                   |
| **Slack / Teams / email / SMS**                  | Notifications and approvals            | Webhook/API        | Interactive approve buttons       |
| **Jira / ServiceNow**                            | Ticketing                              | API                | Incident hand-off                 |
| **Payment/billing (Stripe, Razorpay)**           | Subscriptions                          | API                | Billing only; no card data stored |

Feed terms, quotas and prices change; verify each provider's current licence and limits before relying on it in a paid product.

## **47\. Repository Structure and Environment**

```
cyberdefense-platform/
 |- gateway/            (agent, rule templates, eBPF programs, installers)
 |- platform/
 |   |- api/            (FastAPI app, auth, tenants, incidents, policies)
 |   |- ingestion/      (event intake, schema validation)
 |   |- features/       (shared feature library: train + serve)
 |   |- ml/             (training code, models, evaluation, ONNX export)
 |   |- fusion/         (fusion, calibration, risk scoring)
 |   |- agents/         (LangGraph graphs, tools, prompts, evals)
 |   |- game/           (payoff model, solvers, simulation)
 |   |- safety/         (OPA policies, safety gate, tests)
 |   |- response/       (adapters, rollback, TTL manager)
 |   |- verification/   (checks, probes)
 |   |- intel/          (feed connectors, knowledge base ingestion)
 |- frontend/           (React + TypeScript dashboard)
 |- infra/              (Docker, Helm, Terraform)
 |- lab/                (attack replay, test networks, datasets scripts)
 |- docs/               (architecture, api, models, runbooks, model cards)
 |- tests/              (unit, integration, replay, safety, red-team)
# backend .env (examples)
DATABASE_URL=postgresql://...        REDIS_URL=redis://...
EVENT_BUS_URL=...                    JWT_SECRET=...
KMS_KEY_ID=...                       MLFLOW_TRACKING_URI=...
LLM_PROVIDER=ollama                  ABUSEIPDB_KEY=...   OTX_KEY=...
OPA_URL=http://opa:8181              AUTOMATION_DEFAULT_LEVEL=monitor
```

# **PART J: PLATFORM SECURITY, COMPLIANCE AND OPERATIONS**

## **48\. Securing the Platform Itself**

A security product is a high-value target. The platform must be harder to attack than the customers it protects.

- **Identity:** MFA for all staff and customer admins; SSO; role-based and attribute-based access; just-in-time privileged access.
- **Secrets:** secrets manager or KMS; no secrets in code or images; short-lived credentials; rotation.
- **Encryption:** TLS 1.2+ everywhere, mTLS between gateways and cloud; encryption at rest with per-tenant keys.
- **Tenant isolation:** row-level security, separate keys, per-tenant quotas, noisy-neighbour protection, regular isolation tests.
- **Supply chain:** pinned dependencies, SBOM, signed container images, vulnerability scanning in CI, reviewed third-party rule feeds.
- **Hardening:** least-privilege service accounts, network policies between services, WAF in front of the platform, rate limiting, bot protection.
- **Command integrity:** all commands to gateways are signed, replay-protected and restricted to a fixed command set.
- **Secure development:** code review, SAST/DAST, dependency checks, threat modelling for each new feature, security regression tests.
- **Insider risk:** privileged-action logging, break-glass procedure, customer-visible access logs.

## **49\. Privacy, Compliance and Governance**

| **Area**               | **Approach**                                                                                                                                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Privacy by design**  | Metadata-first collection, pseudonymisation, retention limits, deletion on request, data-residency choices                                                                                                         |
| **India**              | Digital Personal Data Protection Act, 2023 and CERT-In incident-reporting directions; map audit trail and incident timeline to reporting needs (verify current obligations with official sources and legal advice) |
| **Financial sector**   | Sector regulator guidance (for example RBI cyber-security frameworks) and PCI DSS where card data is involved; later-stage requirement                                                                             |
| **Healthcare**         | Patient-data protection expectations; on-prem option; no raw record export                                                                                                                                         |
| **Security standards** | Align with ISO/IEC 27001 controls, SOC 2 criteria, NIST Cybersecurity Framework and NIST incident-handling guidance (SP 800-61); obtain certifications when business justifies cost                                |
| **AI governance**      | Model cards, human oversight, documented limits, bias and error review, customer-controlled automation levels                                                                                                      |
| **Contracts**          | Data processing agreements, clear responsibility for automated actions, service-level objectives                                                                                                                   |

## **50\. Observability, Reliability and Performance**

| **Area**                                                | **Practice**                                                                                                                                                            |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Metrics**                                             | Prometheus + Grafana: ingestion lag, queue depth, inference latency, gateway CPU/memory, action success rate                                                            |
| **Logs and traces**                                     | Structured logs (Loki/ELK); OpenTelemetry tracing across services                                                                                                       |
| **Alerting on the platform**                            | SLO-based alerts; on-call rotation; runbooks                                                                                                                            |
| **Reliability**                                         | Multi-zone deployment; backups with restore tests; disaster-recovery plan; chaos tests on non-production                                                                |
| **Backpressure**                                        | Event bus buffering, sampling under overload, priority lanes for critical events                                                                                        |
| **Performance targets (illustrative, to be validated)** | Detection latency in seconds; policy processing latency in milliseconds; defined packets-per-second target per gateway model; documented concurrent-connection capacity |
| **Capacity planning**                                   | Load tests with replayed traffic; autoscaling inference and stream processors                                                                                           |

# **PART K: TESTING, EVALUATION AND LAB**

## **51\. Test Strategy**

| **Test type**         | **What is verified**                                                                            |
| --------------------- | ----------------------------------------------------------------------------------------------- |
| **Unit tests**        | Feature functions, fusion math, payoff calculations, safety checks, adapters                    |
| **Contract tests**    | Event schemas, API schemas, adapter interfaces                                                  |
| **Integration tests** | Full pipeline from sample events to decision and mock enforcement                               |
| **Replay tests**      | Recorded traffic and PCAP replay (for example with tcpreplay) through the full stack            |
| **Safety-gate tests** | Exhaustive cases: protected assets, blast radius, rate limits, approval routing                 |
| **LLM / agent tests** | Golden incidents, prompt-injection suite, schema-compliance checks                              |
| **Performance tests** | Throughput, latency, memory under load; gateway overhead                                        |
| **Failure tests**     | Cloud outage, model failure, bus failure, gateway crash, half-applied rules, certificate expiry |
| **Security tests**    | Penetration test of the platform, dependency scans, tenant-isolation tests                      |
| **Usability tests**   | Analyst workflows, approval flows, clarity of explanations                                      |

## **52\. Lab Environment and Attack Simulation**

- **Isolated lab only:** virtual machines and containers on a closed network; never test against systems without written permission.
- **Victim services:** deliberately vulnerable applications (for example OWASP Juice Shop, DVWA) and typical servers/databases with synthetic data.
- **Attack simulation:** authorised tools and frameworks such as nmap, hping3, hydra, OWASP ZAP, sqlmap, Atomic Red Team and MITRE Caldera, used to generate labelled test traffic for defensive evaluation.
- **Benign traffic:** realistic background load (browsing, file transfer, API calls) so false positives are measured honestly.
- **Reproducibility:** each scenario is scripted, labelled and versioned so results can be repeated and compared between releases.

### **52.1 Ablation study (core evaluation)**

To prove each layer adds value, the same attack scenarios are run against progressively richer configurations:

| **#** | **Configuration**                 | **Question answered**                                                   |
| ----- | --------------------------------- | ----------------------------------------------------------------------- |
| **A** | Deterministic firewall + IDS only | Baseline                                                                |
| **B** | A + single best ML model          | Does ML help?                                                           |
| **C** | A + multi-model fusion            | Does fusion beat one model?                                             |
| **D** | C + agentic investigation         | Does investigation reduce false positives and analyst time?             |
| **E** | D + game-theoretic selection      | Does it reduce expected loss/disruption versus a fixed response ladder? |
| **F** | E + safety gate + verification    | Does it prevent unsafe actions and confirm containment?                 |

Results are reported with precision, recall, FPR, time to detect/contain, unsafe-action rate and legitimate-traffic impact. This study is the core of any research paper and of the evidence shown to pilot customers.

## **53\. Key Metrics**

| **Category**    | **Metrics**                                                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Detection**   | Accuracy, precision, recall, F1, AUPRC, MCC, false-positive rate, false-negative rate, detection latency                                                                  |
| **Response**    | Mean time to detect, investigate, respond and contain; automated response success rate                                                                                    |
| **Operations**  | CPU, memory, throughput, packets per second, concurrent connections, policy-processing latency                                                                            |
| **AI / agents** | Investigation accuracy, agent decision accuracy, hallucination rate, unsafe-action rate, human-escalation rate, policy-validation failure rate, verification success rate |
| **Business**    | Pilot-to-paid conversion, churn, analyst hours saved, customer-reported disruptions                                                                                       |

# **PART L: DELIVERY PLAN**

## **54\. Development Phases**

The project must not be built all at once. Durations below are planning assumptions for a full team, add up to 59 weeks of full-time effort, and are superseded by the plan in R7 of Revision 2.

| **Phase**                   | **Weeks (assumed)** | **Deliverables**                                                                                                                  | **Exit criteria**                                          |
| --------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **0\. Setup**               | 2                   | Repo, CI, lab network, Docker environment, shared feature library skeleton, event schema                                          | Pipeline runs end to end on sample data                    |
| **1\. Foundation**          | 4                   | Gateway on Linux (nftables), Suricata and Zeek integration, traffic collector, logging, minimal dashboard, deterministic policies | Gateway enforces policy; events visible in dashboard       |
| **2\. Data and features**   | 3                   | Dataset ingestion, cleaning, flow-feature extraction, feature store                                                               | Same features in training and serving; tests pass          |
| **3\. ML detection**        | 6                   | M1-M6 trained, evaluated, cross-dataset tested; inference service; shadow mode                                                    | Targets met on external data and replay                    |
| **4\. Fusion and risk**     | 3                   | Calibration, fusion methods compared, disagreement engine, asset-aware risk                                                       | Fusion beats best single model on agreed metrics           |
| **5\. Agentic layer**       | 6                   | Knowledge graph, RAG base, LangGraph agents, threat-intel connectors, incident timeline                                           | Golden-incident accuracy target met; zero unsafe proposals |
| **6\. Game engine**         | 4                   | Payoff model, solvers, simulation, fallback ladder                                                                                | Beats fixed ladder in simulation on expected loss          |
| **7\. Safety and response** | 5                   | OPA safety gate, adapters, TTL/rollback, approvals, verification service                                                          | Safety test suite passes; rollback verified                |
| **8\. App and data layers** | 8                   | WAF/API inspection, M7; data discovery, M8-M9; posture checks                                                                     | Detects agreed attack scenarios in lab                     |
| **9\. SaaS platform**       | 6                   | Multi-tenancy, onboarding, billing, reports, RBAC, audit export                                                                   | Two tenants isolated and tested                            |
| **10\. Hardening**          | 4                   | Penetration test, load test, failure tests, documentation                                                                         | No critical findings open                                  |
| **11\. Pilot**              | 8+                  | Monitor-only then recommend mode at 2-3 real organisations                                                                        | False-positive rate and customer value measured            |

**Revision 2:** this phase table is superseded by the plan in R7.

## **55\. MVP, V2 and V3**

| **Version** | **Scope**                                                                                                                                                                                                                                                                               |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MVP**     | Gateway with firewall + Suricata; traffic collector; M2, M3 and one anomaly model; fusion and threat score; basic investigation agent with threat-intel lookups; rule-based response ladder; safety gate; dashboard with incident timeline and audit trail; monitor and recommend modes |
| **V2**      | All six core models; full agent set and knowledge graph; game-theoretic engine; autonomous mode for low-risk actions; verification loop; WAF/API layer; multi-gateway management; reports                                                                                               |
| **V3**      | Data layer (discovery, UEBA, exfiltration); extension models; multi-tenant SaaS with billing; MSP console; compliance reports; on-prem package; marketplace of integrations; selective auto-remediation for more actions                                                                |

**Revision 2:** the MVP definition above is superseded by Tier 1 in R3.

**Recommended first deliverable:** a thin vertical slice (Suricata/Zeek feeding two or three models, fusion, one investigation agent, safety gate, dashboard) tested on replayed attacks and then run monitor-only on a real network. This is cheap, publishable and proves the core idea before large investment.

## **56\. Team, Roles and Skills**

| **Role**                        | **Responsibilities**                                             |
| ------------------------------- | ---------------------------------------------------------------- |
| **Security / network engineer** | Firewall, IDS/IPS, WAF, lab, attack scenarios, response adapters |
| **ML engineer**                 | Datasets, features, models, calibration, MLOps                   |
| **Backend engineer**            | APIs, ingestion, event bus, database, multi-tenancy              |
| **AI / agent engineer**         | LangGraph agents, RAG, prompt safety, evaluation                 |
| **Applied maths / game theory** | Payoff models, solvers, simulation                               |
| **Frontend engineer**           | Dashboard, incident timeline, approvals                          |
| **DevOps / SRE**                | CI/CD, infrastructure, observability, reliability                |
| **Product / compliance lead**   | Pilots, customer feedback, privacy and regulatory mapping        |

A small team can combine roles, but the safety gate, the audit trail and the testing of enforcement should always have a named owner.

**Revision 2:** the team is four people, so roles are combined. Roles without a confirmed owner (production firewall operations, MSP partnerships, legal and compliance review) must be filled by a team member, mentor or partner before any Tier 2 work (R11).

## **57\. Git and Release Strategy**

- Branches: main, develop, feature/\*, fix/\*, release/\*; no direct commits to main.
- Every change needs review and passing CI: unit, contract, safety-gate and prompt-injection tests.
- Policies, prompts, feature definitions and model versions are versioned and released together with code.
- Staged releases: internal lab, shadow, canary tenants, general availability; automatic rollback on error budgets.

## **58\. Risks and Mitigations**

| **Risk**                                   | **Impact**                               | **Mitigation**                                                                                          |
| ------------------------------------------ | ---------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **Scope too large for team**               | Nothing ships                            | Thin vertical slice first; phase gates; build on Suricata/Zeek/nftables rather than from scratch        |
| **Public-dataset results do not transfer** | Poor real-world accuracy                 | Cross-dataset tests, shadow mode, pilot data, continuous retraining                                     |
| **False positives block real users**       | Customer trust lost                      | Monitor/recommend modes first; safety gate; least-disruption actions; fast rollback                     |
| **LLM errors or prompt injection**         | Wrong investigations or unsafe proposals | Structured outputs, tool allowlists, safety gate, evaluation and red-team tests                         |
| **Game-theory parameters are estimates**   | Questionable decisions                   | Show assumptions, calibrate with verification feedback, deterministic fallback                          |
| **Platform compromise**                    | Attacker controls many customers         | Signed commands, tenant isolation, hardened infra, restricted command set, independent security testing |
| **Regulatory and privacy issues**          | Cannot sell to regulated sectors         | Metadata-first design, on-prem option, legal review, phased entry into healthcare and finance           |
| **Incumbent competition**                  | Hard differentiation                     | Focus on verified outcomes, audit trail, under-served segments and MSP channel                          |
| **Data scarcity**                          | Weak models                              | Lab generation, partnerships, customer pilots with consent, synthetic augmentation with care            |

## **59\. Success Criteria**

The platform is successful when all of the following can be demonstrated:

### **Detection and decision**

- Detects the agreed attack scenarios across network, application and data layers with the agreed precision and recall on external data and live pilots.
- Combines models into a calibrated score with explanations; investigates and correlates alerts into incidents automatically.
- Chooses a response with an expected-loss rationale and shows runner-up options.

### **Safety and trust**

- No action bypasses the safety gate; unsafe-action rate is zero in the test suite and monitored in production.
- Every action is logged, explainable, time-limited and reversible where possible.
- The platform keeps protecting the network when the cloud, models or LLM are unavailable.

### **Outcome**

- Verification confirms containment or escalates; legitimate traffic remains available.
- Measured improvements versus the baseline in the ablation study: time to detect, time to contain, false positives and analyst effort.
- At least three organisations or MSPs sign paid pilots, and at least two continue after the pilot ends (gates G3 and G5 of Revision 2).

## **60\. Final Architecture Decision and Technology Lock**

```
         AUTONOMOUS CYBER DEFENSE PLATFORM
  Network + Application/API + Data in one SaaS
                    |
   Gateway (nftables, Suricata, Zeek, WAF) --mTLS--> Cloud platform
                    |
   Events -> Features -> 6 core + 3 extension models -> Fusion -> Risk
          -> Agentic investigation (LangGraph, RAG, knowledge graph)
          -> Game-theoretic decision (expected loss, Stackelberg, Bayesian)
          -> Safety gate (OPA) -> Response engine -> Verification -> Feedback
```

| **Layer**       | **Technology**                                                                      |
| --------------- | ----------------------------------------------------------------------------------- |
| **Gateway**     | Linux, nftables, eBPF/XDP, Suricata, Zeek, ModSecurity/Coraza, Go agent             |
| **Backend**     | Python, FastAPI, PostgreSQL, pgvector, Redis, Kafka/NATS, TimescaleDB or ClickHouse |
| **ML**          | scikit-learn, XGBoost, LightGBM, PyTorch, ONNX Runtime, MLflow, SHAP                |
| **Agents**      | LangGraph, LangChain (where useful), provider abstraction (Ollama / hosted API)     |
| **Game theory** | NumPy, SciPy, cvxpy, nashpy, OpenSpiel, CyberBattleSim/CybORG for simulation        |
| **Safety**      | Open Policy Agent (Rego), signed commands, hash-chained audit log                   |
| **Graph**       | Neo4j or PostgreSQL + Apache AGE                                                    |
| **Frontend**    | React, TypeScript, Vite, Tailwind, WebSocket                                        |
| **Infra**       | Docker, Kubernetes (when needed), Terraform, Prometheus, Grafana, OpenTelemetry     |
| **Cloud**       | AWS, Azure or GCP; on-prem package for regulated customers                          |

**Revision 2:** the architecture above is the long-term target. The MVP architecture and stack are in R4, and technology choices marked Tier 2 or Tier 3 are not locked for the MVP.

## **61\. Final Principle**

**Security teams should not have to trust a black box. They should be able to see what the platform saw, what it concluded, what it chose to do and why, what safety checks it passed, and what happened afterwards, and they should always be able to override it.**

Deterministic controls provide the floor. Machine learning provides detection. Fusion provides robustness. Agents provide investigation. Game theory, a deferred research module, may later refine response selection. The safety gate provides protection from the AI itself. Verification provides proof. Together they move an organisation from passive alerts to adaptive, auditable, increasingly autonomous cyber defense.

## **62\. Reference Frameworks and Standards**

- MITRE ATT&CK for adversary technique mapping.
- OWASP Top 10 and OWASP API Security Top 10 for application-layer coverage.
- NIST Cybersecurity Framework and NIST SP 800-61 for incident handling.
- CIS Critical Security Controls for baseline hardening.
- ISO/IEC 27001 and SOC 2 for organisational controls.
- CISA Known Exploited Vulnerabilities catalogue, NVD/CVE and FIRST EPSS for vulnerability prioritisation.
- Public datasets: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, CIC-DDoS2019, CTU-13, Bot-IoT, ToN-IoT.

## **63\. Glossary**

| **Term**             | **Meaning**                                                               |
| -------------------- | ------------------------------------------------------------------------- |
| **IDS / IPS**        | Intrusion Detection / Prevention System                                   |
| **WAF**              | Web Application Firewall                                                  |
| **UEBA**             | User and Entity Behaviour Analytics                                       |
| **IOC**              | Indicator of Compromise (IP, domain, hash, fingerprint)                   |
| **C2**               | Command and control (attacker-to-malware communication)                   |
| **Blast radius**     | Amount of users, services or assets affected by an action                 |
| **TTL**              | Time to live; the time after which an action expires automatically        |
| **Stackelberg game** | Leader commits to a strategy first; follower best-responds                |
| **Calibration**      | Making predicted probabilities match observed frequencies                 |
| **Shadow mode**      | Running a model on live traffic without letting it act                    |
| **RAG**              | Retrieval-Augmented Generation; the LLM answers using retrieved documents |
| **SBOM**             | Software Bill of Materials                                                |
| **mTLS**             | Mutual TLS: both client and server authenticate with certificates         |

# **PART M: RESEARCH AND VALIDATION MASTER FRAMEWORK**

## **64\. Purpose and Evidence Principle**

The earlier parts describe what the platform will do and how. This part defines how every claim about the platform is **researched, tested and either proven or left clearly marked as unproven**. It applies to the whole product, not only the ML models: firewall, API security, data protection, threat intelligence, AI agents, game theory, autonomous response, multi-tenant SaaS and compliance each need their own research basis and validation plan.

**Core rule:** a framework reference does not prove a feature is secure. A successful simulation does not prove the platform will stop real attacks. A benchmark score does not establish production readiness. Security claims are upgraded only when the matching evidence exists.

NIST CSF 2.0 provides the overall risk-management structure, NIST SP 800-61 Rev. 3 covers incident response, and the NIST AI Risk Management Framework covers AI risk across the lifecycle. These are complementary references that guide design and evaluation. They are not evidence that our implementation is effective.

## **65\. Three Kinds of Statements and Status Labels**

| **Statement type**           | **Meaning**                                                                                             | **Example**                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Research-supported**       | A published source supports the underlying method or design principle                                   | Calibrated probabilities are needed before combining model outputs                                              |
| **Experimentally validated** | Our implementation passed a documented test under stated conditions                                     | M3 detected the replayed flood scenarios at the agreed recall and FPR on our lab traffic                        |
| **Production-validated**     | The system showed acceptable performance in an authorised real-world deployment under stated conditions | A pilot network ran in shadow mode for an agreed period with measured false-positive rate and analyst agreement |
| **Not yet validated**        | The design is proposed; sufficient evidence has not been collected                                      | Game-theoretic selection reduces expected loss versus a fixed ladder on real customers                          |

| **Acceptance status** | **Use**                                                                                                           |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **PASS**              | Acceptance criteria met under documented conditions, with evidence attached and reviewed                          |
| **FAIL**              | Criteria not met; defect or redesign required; claim must not be made                                             |
| **CONDITIONAL**       | Met only under limited conditions (named dataset, environment, tenant size); conditions stated beside every claim |
| **NOT TESTED**        | No qualifying evidence yet; the feature stays labelled 'proposed' in all customer and investor material           |

These labels must remain visible in the specification, dashboards of model quality, sales material and pitch documents. Marketing language may not be stronger than the status.

## **66\. Five-Part Evidence Record for Every Component**

Each major component (and each significant technical decision) keeps one evidence record with five sections:

| **Section**                        | **Question it answers**                                                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **1\. Research basis**             | Which established research, standards, security frameworks or official technical documentation support the approach? |
| **2\. Technical justification**    | Why is this approach suitable, and which alternatives were compared (at least two for important choices)?            |
| **3\. Implementation methodology** | How is it built, what data and dependencies are needed, and how does it integrate with the rest of the platform?     |
| **4\. Validation methodology**     | Which experiments, baselines, metrics, test cases and acceptance criteria decide whether it works?                   |
| **5\. Evidence and limitations**   | What results prove the claim, what remains unproven, and what failure modes or trade-offs exist?                     |

**Pre-registration:** acceptance thresholds (for example the maximum false-positive rate or minimum recall) are written down **before** the experiment is run. Thresholds chosen after seeing results are not acceptable evidence.

## **67\. Required Research Methodology**

For each feature and major technical decision, the following twelve steps are mandatory:

| **#**  | **Step**               | **Requirement**                                                                                 |
| ------ | ---------------------- | ----------------------------------------------------------------------------------------------- |
| **1**  | Research question      | State the specific security problem being solved                                                |
| **2**  | Literature review      | Identify relevant papers, standards, official documentation and credible technical evaluations  |
| **3**  | Evidence quality       | Record publication date, source type, assumptions, limitations and relevance to our environment |
| **4**  | Alternative approaches | Compare at least two plausible approaches for important architectural or model choices          |
| **5**  | Hypothesis             | State the improvement expected and how it will be measured                                      |
| **6**  | Experimental design    | Specify dataset or test environment, baseline, splits, metrics, repetitions and controls        |
| **7**  | Implementation         | Record configuration, dependencies, model versions, code version and reproducible steps         |
| **8**  | Results                | Record measured outcomes, uncertainty, failures and resource costs                              |
| **9**  | Security validation    | Test abuse cases, adversarial inputs, privilege boundaries, failure modes and unsafe behaviour  |
| **10** | Acceptance decision    | Mark PASS / FAIL / CONDITIONAL / NOT TESTED with evidence attached                              |
| **11** | Limitations            | Document what the result does not demonstrate                                                   |
| **12** | Independent review     | Require another reviewer for high-impact controls and autonomous actions                        |

## **68\. Evidence Artifacts and Test Record**

Every significant validation produces an auditable record stored in version control (large datasets by reference with hashes).

```
research/
 |- literature-review/          |- security-test-cases/
 |- standards-mapping/          |- adversarial-test-results/
 |- threat-models/              |- performance-benchmarks/
 |- hypotheses/                 |- incident-simulation-results/
 |- experimental-protocols/     |- compliance-evidence/
 |- datasets-and-provenance/    |- limitations-and-risks/
 |- baseline-results/           |- release-validation/
 |- model-evaluation/
Test ID:               Subsystem:
Research question:     Source references:
Hypothesis:            Environment:
Dataset or scenario:   Baseline:
Procedure:             Expected result:
Observed result:       Metrics:
Evidence artifact:     Known limitations:
Reviewer:              Status (PASS/FAIL/CONDITIONAL/NOT TESTED):
Date:
```

## **69\. Subsystem Evidence Records**

Each table below is the starting evidence record for one subsystem. The research basis lists the kinds of sources to be reviewed and recorded in full in literature-review/; results sections stay empty until tests are run.

### **69.1 Firewall and IDS/IPS**

| **Section**                  | **Content**                                                                                                                                                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | NIST SP 800-41 (firewall guidance) and SP 800-94 (intrusion detection and prevention); TCP/IP protocol standards (RFCs); Suricata, Zeek and nftables official documentation; CIS benchmarks                                               |
| **Technical justification**  | Compare nftables vs iptables, XDP/eBPF vs kernel netfilter, Suricata vs Snort; choose by throughput, rule ecosystem, maintainability                                                                                                      |
| **Implementation**           | nftables policy templates, Suricata with maintained rule sets, Zeek logs, signed policy distribution, versioned rollback                                                                                                                  |
| **Validation**               | Rule-coverage tests against known attack traces; false-positive rate on benign traffic; throughput and latency under load; evasion/bypass tests (fragmentation, protocol edge cases); policy conflict tests; fail-safe behaviour on crash |
| **Evidence and limitations** | Signature coverage is limited to known patterns; IPS blocking can cause outages; performance depends on hardware; encrypted traffic limits payload inspection                                                                             |

### **69.2 WAF and API Security**

| **Section**                  | **Content**                                                                                                                                                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | OWASP API Security Top 10 (awareness document, not a test suite), OWASP Top 10, OWASP ASVS, OWASP Core Rule Set documentation                                                                            |
| **Technical justification**  | Compare signature-based (CRS), positive-security (OpenAPI schema enforcement) and ML request-anomaly approaches; likely a layered combination                                                            |
| **Implementation**           | ModSecurity/Coraza + CRS, OpenAPI validation, bot/credential-stuffing signals, rate limits, per-API policies                                                                                             |
| **Validation**               | Authorization (BOLA/BFLA) test cases; injection and abuse suites; schema-enforcement tests; regression tests per release; false-positive rate on real application traffic; paranoia-level tuning results |
| **Evidence and limitations** | Business-logic flaws are hard to detect automatically; CRS needs per-application tuning; the Top 10 list does not certify completeness                                                                   |

### **69.3 Data Security and DLP**

| **Section**                  | **Content**                                                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Data-classification, access-control, encryption and privacy guidance (NIST SP 800-53 control families, NIST Privacy Framework, ISO/IEC 27001 Annex A); documentation of Microsoft Presidio and checksum algorithms                                                   |
| **Technical justification**  | Compare regex + checksum, NER-based and ML classifiers for discovery; compare agent-based vs agentless collection for access monitoring                                                                                                                              |
| **Implementation**           | Read-only connectors, sampling-based classification, labels stored without content, database audit-log ingestion, exfiltration baselines                                                                                                                             |
| **Validation**               | Discovery precision/recall on a labelled synthetic and consented real corpus; per-identifier-type results; unauthorised-access test cases; exfiltration scenarios (bulk read, staging, DNS tunnelling); privacy test that no raw sensitive content leaves the tenant |
| **Evidence and limitations** | Unstructured data and unusual formats reduce recall; encrypted fields cannot be classified; monitoring requires privileged access that itself must be protected                                                                                                      |

### **69.4 ML Detection Engine**

| **Section**                  | **Content**                                                                                                                                                                                                                                                                                        |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Dataset papers (CIC-IDS2017 by Sharafaldin et al.; UNSW-NB15 by Moustafa and Slay); critical studies of data quality (Engelen et al., on CIC-IDS2017 errors); Sommer and Paxson on machine learning for intrusion detection; Arp et al., "Dos and Don'ts of Machine Learning in Computer Security" |
| **Technical justification**  | Compare tree ensembles vs neural models vs unsupervised anomaly detection per task; compare against rule-only and simple-ML baselines                                                                                                                                                              |
| **Implementation**           | Shared feature library for training and serving; versioned datasets, features and models; MLflow registry; shadow mode                                                                                                                                                                             |
| **Validation**               | See section 70 for the full protocol                                                                                                                                                                                                                                                               |
| **Evidence and limitations** | Public benchmarks are old and partly synthetic; high scores can reflect artefacts; performance on unseen attacks and real encrypted traffic is unproven until pilots                                                                                                                               |

### **69.5 Model Fusion and Risk Scoring**

| **Section**                  | **Content**                                                                                                                                                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Ensemble and stacked generalisation (Wolpert); probability calibration (Platt scaling, isotonic regression; Guo et al. on neural-network calibration); Dempster-Shafer evidence theory; decision theory for risk |
| **Technical justification**  | Compare simple/weighted average, log-odds fusion, stacking, noisy-OR and Dempster-Shafer; compare with the best single model                                                                                     |
| **Implementation**           | Calibration per model, fusion method selected by validation data, disagreement engine, asset-aware risk formula                                                                                                  |
| **Validation**               | Calibration error (ECE, Brier); ranking quality (AUPRC); ablation: remove each model and measure change; performance per threat category; behaviour when a model is missing or stale                             |
| **Evidence and limitations** | Fusion assumes models are not all wrong in the same way; correlated models inflate confidence; asset impact values are estimates                                                                                 |

### **69.6 Threat Intelligence**

| **Section**                  | **Content**                                                                                                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Research basis**           | STIX/TAXII standards, MITRE ATT&CK, CISA KEV, FIRST EPSS documentation, traffic-light protocol for sharing; studies on indicator quality and decay                       |
| **Technical justification**  | Compare feeds on coverage, precision, timeliness and licence cost; compare matching-only vs enrichment-with-context use                                                  |
| **Implementation**           | Connectors, normalisation to STIX-like objects, scoring with age decay, source reliability weights, tenant-private intel                                                 |
| **Validation**               | Indicator precision on known-benign traffic; overlap and uniqueness between feeds; time from public disclosure to ingestion; false-block rate caused by stale indicators |
| **Evidence and limitations** | Free feeds contain stale or shared-infrastructure indicators; IOC matches are weak evidence alone; licence terms may restrict commercial use                             |

### **69.7 AI SOC Analyst (Agentic Investigation)**

| **Section**                  | **Content**                                                                                                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Research basis**           | NIST SP 800-61 Rev. 3; NIST AI RMF and its Generative AI Profile; OWASP Top 10 for LLM Applications; research on indirect prompt injection (Greshake et al.); MITRE ATT&CK for technique mapping |
| **Technical justification**  | Compare fixed playbooks, LLM-agent workflows and hybrid (LLM inside a deterministic state machine); compare local vs hosted models on accuracy and privacy                                       |
| **Implementation**           | LangGraph state machine, read-only tools, structured outputs, citation of evidence, provider abstraction                                                                                         |
| **Validation**               | See section 71 for the full protocol                                                                                                                                                             |
| **Evidence and limitations** | LLMs can hallucinate or be steered by hostile text; evaluation sets may not cover novel attacks; results depend on the model version and must be re-run when it changes                          |

### **69.8 RAG and Knowledge Graph**

| **Section**                  | **Content**                                                                                                                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Retrieval-augmented generation (Lewis et al.); information-retrieval evaluation practice; graph data-modelling and provenance research; access-control models                                                                                           |
| **Technical justification**  | Compare vector-only, keyword-only and hybrid retrieval; compare Neo4j and PostgreSQL with Apache AGE for graph queries                                                                                                                                  |
| **Implementation**           | pgvector with metadata, hybrid retrieval with re-ranking, provenance on every chunk and edge, per-tenant partitions                                                                                                                                     |
| **Validation**               | Retrieval quality (recall@k, MRR) on a labelled question set; evidence-attribution correctness; stale-intelligence handling; cross-tenant leakage tests; prompt-injection through retrieved documents; graph-query correctness against known topologies |
| **Evidence and limitations** | Retrieval can return outdated or irrelevant text; graph completeness depends on asset-inventory quality                                                                                                                                                 |

### **69.9 Autonomous Response and Safety Gate**

| **Section**                  | **Content**                                                                                                                                                                                                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Autonomic computing monitor-analyse-plan-execute loop (Kephart and Chess); NIST SP 800-160 systems security engineering; policy-as-code practice (Open Policy Agent); safe change-management practice                                                    |
| **Technical justification**  | Compare rule-only policy gates, ML-assisted gates and OPA policy-as-code; deterministic gate chosen so it can be tested exhaustively                                                                                                                     |
| **Implementation**           | Safety-gate checks, approval routing, TTLs, rollback, signed commands, adapters with dry-run                                                                                                                                                             |
| **Validation**               | Unauthorised-action rate (target zero in test suite); containment success; collateral impact on legitimate traffic; rollback success; protected-asset bypass attempts; attacker-induced block-flood tests; verification outcome after simulated response |
| **Evidence and limitations** | Incorrect asset criticality or protected-list data weakens the gate; automation can amplify mistakes, so autonomous levels stay opt-in                                                                                                                   |

### **69.10 Game-Theoretic Defence**

| **Section**                  | **Content**                                                                                                                                                                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Research basis**           | Manshaei et al., game theory for network security and privacy; Tambe, security games and deployed systems; Conitzer and Sandholm, optimal strategy to commit to; Paruchuri et al., DOBSS                                             |
| **Technical justification**  | Compare fixed response ladder, expected-loss minimisation, Stackelberg/Bayesian models and reinforcement learning in simulation                                                                                                      |
| **Implementation**           | Payoff model, solver library, simulation environment, deterministic fallback                                                                                                                                                         |
| **Validation**               | Baseline comparison against the fixed ladder in simulation (expected loss, disruption); sensitivity analysis on payoff parameters; robustness when attacker behaviour differs from the assumed type; ablation E vs D in section 52.1 |
| **Evidence and limitations** | Payoffs and attacker models are assumptions; benefit on real attackers is unproven until pilots; results shown as comparisons with visible assumptions, never as proof of optimality                                                 |

### **69.11 SaaS and Infrastructure**

| **Section**                  | **Content**                                                                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | NIST SP 800-207 (Zero Trust Architecture); NIST SP 800-218 (Secure Software Development Framework); OWASP ASVS; Cloud Security Alliance guidance; cloud-provider security documentation                 |
| **Technical justification**  | Compare shared-schema with row-level security vs schema-per-tenant vs database-per-tenant on isolation strength, cost and operability                                                                   |
| **Implementation**           | Row-level security, per-tenant keys, mTLS, signed images, SBOM, least-privilege roles                                                                                                                   |
| **Validation**               | Tenant-isolation tests (cross-tenant read/write attempts at API, database, queue and cache); penetration tests; availability and recovery drills; access-control reviews; dependency and image scanning |
| **Evidence and limitations** | Isolation guarantees depend on correct configuration everywhere; third-party cloud and library vulnerabilities remain a residual risk                                                                   |

### **69.12 Compliance and Audit**

| **Section**                  | **Content**                                                                                                                                                                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Research basis**           | Applicable laws and frameworks for the specific customer: for example DPDP Act 2023 and the notified DPDP Rules, RBI IT governance directions for regulated entities, CERT-In directions, ISO/IEC 27001, SOC 2, PCI DSS where card data is processed |
| **Technical justification**  | Compare mapping controls to a single master control set vs separate per-regulation checklists                                                                                                                                                        |
| **Implementation**           | Control-to-feature-to-evidence matrix, retention settings, exportable audit logs, reports                                                                                                                                                            |
| **Validation**               | Gap analysis per customer; evidence completeness checks; retention and deletion tests; independent legal/compliance review                                                                                                                           |
| **Evidence and limitations** | Applicability depends on the customer and deployment; the product helps produce evidence but does not by itself make a customer compliant                                                                                                            |

## **70\. Validating the ML Detection Engine**

The models are compared against meaningful baselines rather than trained and reported by accuracy alone.

- Document dataset origin, licence, provenance and collection period.
- Inspect class imbalance, missing values, duplicates and possible label errors.
- Prevent train/test contamination and temporal leakage (split by time or session).
- Establish simple rule-based and conventional ML baselines.
- Evaluate each model independently before testing model fusion.
- Report precision, recall, F1, PR-AUC and false-positive rate.
- Report inference latency, throughput and resource consumption.
- Evaluate per attack category and on benign traffic.
- Test temporal drift and previously unseen scenarios.
- Run ablation studies to show whether each model contributes value.
- Record confidence intervals or variability across repeated runs.
- Version the dataset, features, code, configuration and trained model.
- Test the deployed pipeline, not only offline notebook results.

**Important:** accuracy alone is insufficient for a cybersecurity detector. A model can have high accuracy and still miss rare attacks or generate an unusable number of false alarms.

## **71\. Validating the AI SOC Analyst**

- Build a labelled set of realistic incident scenarios, including benign events, ambiguous cases and multi-stage attacks.
- Give the system only the telemetry and tools it is authorised to access.
- Compare generated timelines against ground-truth event sequences.
- Measure whether cited evidence actually supports each conclusion.
- Measure false incident escalation and missed incidents.
- Compare findings with qualified human reviewers (agreement rate).
- Test malicious log entries and prompt injection.
- Test missing, contradictory and stale evidence.
- Test tool timeouts, unavailable integrations and partial telemetry.
- Verify the agent cannot exceed its permissions.
- Require policy validation and approval for high-impact actions.
- Verify the real-world outcome after a simulated or authorised response.

The NIST AI RMF emphasises validity, reliability, safety, security, resilience, transparency, explainability and privacy across the AI lifecycle. These become explicit evaluation categories for the agents:

| **Quality**                         | **How it is evaluated for the SOC agents**                                         |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| **Validity and reliability**        | Accuracy against ground truth; consistency across repeated runs and model versions |
| **Safety**                          | Unsafe-proposal rate; behaviour under ambiguous or conflicting evidence            |
| **Security and resilience**         | Prompt-injection suite; behaviour when tools fail; permission-boundary tests       |
| **Transparency and explainability** | Every conclusion cites evidence; reviewers can follow the reasoning chain          |
| **Privacy**                         | No cross-tenant data in context; sensitive content minimised in prompts and logs   |

## **72\. Compliance Mapping for India**

For banking and personal-data deployments, compliance is mapped to **actual controls and evidence**, assessed per customer. Applicability is never assumed universally.

| **Item**                                  | **Approach**                                                                                                                                                                                                              |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DPDP Act 2023 and notified DPDP Rules** | Confirm the current notified rules and implementation timeline from the official MeitY publication; map obligations (security safeguards, breach handling, retention, processor duties) to platform controls and evidence |
| **RBI IT governance directions**          | Check applicability to the specific regulated customer (bank, NBFC and so on); map relevant requirements to controls such as access control, logging, incident handling and vendor oversight                              |
| **CERT-In directions**                    | Map incident-reporting and log-retention expectations to the incident timeline and audit export                                                                                                                           |
| **Evidence matrix**                       | For each requirement: platform control, test or configuration evidence, owner, review date, residual gap                                                                                                                  |
| **Review**                                | Independent legal and compliance review before any statement of compliance appears in customer material                                                                                                                   |

## **73\. Release Gate and Independent Review**

- A feature may be released as **'validated'** only if its status is PASS with attached evidence; CONDITIONAL features ship with their conditions visible.
- NOT TESTED features may be shown only as roadmap items, never as current capabilities.
- High-impact controls and all autonomous action types require review by someone who did not build them.
- Any change to a model, prompt, policy or safety rule re-opens the affected tests.
- Release validation records are stored in release-validation/ with the exact code, model and configuration versions.

## **74\. Initial Evidence Status Register**

Status at the time of this specification: design basis identified for each subsystem; no experiments run yet. This table is updated as evidence is produced.

| **Subsystem**                           | **Research basis** | **Experimental validation** | **Acceptance status** |
| --------------------------------------- | ------------------ | --------------------------- | --------------------- |
| **Firewall and IDS/IPS**                | Identified         | Not started                 | NOT TESTED            |
| **WAF and API security**                | Identified         | Not started                 | NOT TESTED            |
| **Data security and DLP**               | Identified         | Not started                 | NOT TESTED            |
| **ML detection engine**                 | Identified         | Not started                 | NOT TESTED            |
| **Model fusion and risk scoring**       | Identified         | Not started                 | NOT TESTED            |
| **Threat intelligence**                 | Identified         | Not started                 | NOT TESTED            |
| **AI SOC analyst**                      | Identified         | Not started                 | NOT TESTED            |
| **RAG and knowledge graph**             | Identified         | Not started                 | NOT TESTED            |
| **Autonomous response and safety gate** | Identified         | Not started                 | NOT TESTED            |
| **Game-theoretic defence**              | Identified         | Not started                 | NOT TESTED            |
| **SaaS and infrastructure**             | Identified         | Not started                 | NOT TESTED            |
| **Compliance and audit**                | Identified         | Not started                 | NOT TESTED            |

## **75\. Source Register (to Be Completed During Literature Review)**

Sources named in this document are starting points. Each is recorded in literature-review/ with date, type, assumptions, limitations and relevance, and checked against its current official version before use.

| **Area**                       | **Starting sources**                                                                                                                                       |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Risk and incident response** | NIST CSF 2.0; NIST SP 800-61 Rev. 3; NIST SP 800-53; NIST SP 800-207; NIST SP 800-218                                                                      |
| **AI risk**                    | NIST AI RMF and Generative AI Profile; OWASP Top 10 for LLM Applications                                                                                   |
| **Application security**       | OWASP API Security Top 10 (2023); OWASP Top 10; OWASP ASVS; OWASP Core Rule Set                                                                            |
| **Network security**           | NIST SP 800-41; NIST SP 800-94; Suricata, Zeek and nftables documentation; CIS Benchmarks                                                                  |
| **ML for intrusion detection** | Sharafaldin et al. (CIC-IDS2017); Moustafa and Slay (UNSW-NB15); Engelen et al. (CIC-IDS2017 troubleshooting); Sommer and Paxson (2010); Arp et al. (2022) |
| **Calibration and fusion**     | Platt scaling; isotonic regression; Guo et al. (2017); Wolpert (stacked generalisation)                                                                    |
| **LLM agents and RAG**         | Lewis et al. (2020, retrieval-augmented generation); Greshake et al. (2023, indirect prompt injection)                                                     |
| **Game theory**                | Manshaei et al. (2013); Tambe (2011); Conitzer and Sandholm (2006); Paruchuri et al. (2008)                                                                |
| **Autonomic systems**          | Kephart and Chess (2003); NIST SP 800-160                                                                                                                  |
| **Threat intelligence**        | OASIS STIX/TAXII; MITRE ATT&CK; CISA KEV; FIRST EPSS                                                                                                       |
| **India compliance**           | DPDP Act 2023 and notified Rules (MeitY); RBI directions applicable to the customer; CERT-In directions                                                    |

# **PART N: REVIEW CORRECTIONS AND IMPLEMENTATION CONTRACT**

## **76\. Review Outcome and How It Is Used**

An independent review of this specification concluded that it is a strong architecture and research-planning document but **not yet evidence that the platform works in practice**. Its sections on evaluation, ablation, source registration and evidence status are a plan for generating evidence, not evidence already generated. The review recommended keeping the document as the master specification, fixing a small number of technical issues, and building a smaller end-to-end slice before implementing every subsystem.

This part records those corrections. Where it conflicts with an earlier section, **this part takes precedence**. Priorities: P0 must be fixed before any implementation relies on the section; P1 before pilots.

## **77\. Technical Corrections**

### **77.1 Fusion scores must be mathematically consistent (P0)**

- The six-model average in section 18 is an illustrative score. It is not a calibrated attack probability, and the confidence and probability values in the example output are formatting examples only.
- Define and document: the fusion method, the calibration dataset, how uncertainty is computed, how missing or stale models are handled, and the acceptance tests.
- Acceptance test: fusion must beat the best single model on held-out and external data (AUPRC, calibration error, false-positive rate at fixed recall). If it does not, the simpler model is used.
- Rule: a high score must never be presented to customers as a high probability of a real attack until calibration evidence exists.

### **77.2 Limits of autonomous response (P0)**

Two different requirements must be tested separately: (a) **no action reaches enforcement without passing the gate**, and (b) **the gate never approves an action it should reject**. Passing (a) says nothing about (b).

| **Adversarial gate test**                                               | **Pass condition**                                             |
| ----------------------------------------------------------------------- | -------------------------------------------------------------- |
| **Expired or revoked credentials**                                      | Action rejected; event logged                                  |
| **Replayed or duplicated commands**                                     | Second execution has no effect (idempotent) and is flagged     |
| **Stale asset criticality or protected-list data**                      | Gate falls back to the stricter level or requires approval     |
| **Compromised or revoked gateway certificate**                          | Commands to and from that gateway rejected; incident raised    |
| **Tenant-boundary violation (action targeting another tenant's asset)** | Rejected at API, queue and adapter level                       |
| **Rollback failure**                                                    | Escalation to a human with the exact residual state shown      |
| **Approval service unavailable**                                        | High-impact actions wait or fail safe; they never auto-approve |
| **Attacker-induced block flood**                                        | Rate-of-change limit stops automation and alerts               |

**Autonomous action boundary at first release:**

| **Level**        | **Allowed without human approval**                                    | **Condition**                                         |
| ---------------- | --------------------------------------------------------------------- | ----------------------------------------------------- |
| **L0 to L1**     | Log, tag, monitor, increase visibility                                | Always                                                |
| **L2**           | Rate-limit, challenge, stricter inspection (reversible, time-limited) | Opt-in per tenant and asset group, after shadow pilot |
| **L3**           | Block with TTL on non-critical assets                                 | Only after pilot evidence and customer sign-off       |
| **L4 and above** | Quarantine, role restriction, segment isolation                       | Always human approval                                 |

Protected assets (management plane, DNS, identity provider, payment gateway, life-critical devices, customer-defined list) are never automatically acted on at any level above L1.

### **77.3 Scope and delivery timeline (P0)**

The durations in section 54 are planning assumptions, not demonstrated delivery evidence. The thin vertical slice in section 81 is the first release. The full nine-model catalogue, the game-theoretic engine, application and data layers and the commercial SaaS follow only after that slice proves the central proposition.

### **77.4 Gateway enforcement design (P1)**

The gateway tools have different responsibilities and must not be treated as interchangeable.

| **Component**            | **Role**                                                                                          | **Constraints and ownership**                                |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **nftables / netfilter** | Stateful L3/L4 filtering, NAT, rate limits; the authoritative enforcement point for allow/deny    | Owns firewall policy; rules generated from one policy source |
| **XDP / eBPF**           | Early stateless drops and fast filtering of known-bad sources and floods                          | Limited state; used for pre-filtering, not full policy       |
| **Suricata**             | Passive IDS, or inline IPS (for example via NFQUEUE or AF_PACKET inline mode) on selected traffic | Overload behaviour must be defined; IPS only after tuning    |
| **Zeek**                 | Passive protocol metadata and logs                                                                | Never enforces; feeds features and evidence                  |
| **WAF / API proxy**      | L7 inspection of HTTP(S) to protected applications                                                | Sees only traffic routed through it; owns web rules          |

- A single **policy compiler** produces each component's rules from one versioned policy, so ownership and conflicts are explicit.
- Document for each deployment: where traffic is mirrored or inline, where state lives, and what each component can and cannot see.
- **Fail-open vs fail-closed** is defined per traffic class and asset, not globally.

| **Traffic class**                                | **Default on inspection overload or crash**                | **Reason**                                |
| ------------------------------------------------ | ---------------------------------------------------------- | ----------------------------------------- |
| **Management plane and gateway control channel** | Fail-closed to a safe known policy                         | Prevents takeover of the control path     |
| **Critical business services (customer-chosen)** | Fail-open for inspection, keep stateful firewall and alert | Availability usually outweighs inspection |
| **Sensitive data zones**                         | Fail-closed for new outbound sessions                      | Limits exfiltration during blind periods  |
| **Guest, IoT, untrusted segments**               | Fail-closed or restricted                                  | Lower availability impact, higher risk    |

These defaults are starting points that must be agreed with each customer and tested in failure drills.

### **77.5 DDoS: local versus upstream mitigation (P1)**

- A gateway can detect and mitigate attacks that **do not saturate the customer's internet link or the gateway's own capacity**: floods that are small relative to the uplink, application-layer abuse, connection-table exhaustion, scanning and brute force.
- Volumetric attacks that fill the link before traffic reaches the gateway cannot be solved locally. They need an ISP, CDN, cloud provider or scrubbing service.
- The platform defines trigger thresholds (for example link utilisation and gateway CPU) at which it requests upstream mitigation, and integrates with provider APIs or ISP processes such as remote-triggered blackholing where available.
- Product claims must say what is covered locally and what requires an upstream integration.

### **77.6 Risk scale and uncertainty policy (P1)**

| **Factor**                | **Definition and normalisation (to be calibrated)**                                                |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| **P(attack)**             | 0 to 1; only a calibrated fused probability may be used here                                       |
| **Impact**                | Normalised 0 to 1 from asset criticality and data sensitivity levels; levels defined per customer  |
| **Exposure**              | 0 to 1 from internet-facing status, reachable paths, exploitable vulnerabilities (CVSS, EPSS, KEV) |
| **Control effectiveness** | 0 to 1 from verified controls (patch, segmentation, WAF rule); unverified controls count as 0      |

- Bands (low, medium, high, critical) are set by calibrating the score against labelled incidents, not by intuition.
- Sensitivity test: perturb asset metadata (for example one level up or down) and measure how often the response level changes; large swings mean the metadata process must improve.
- **Uncertainty policy:** when model disagreement exceeds a defined threshold, or inputs are missing, the action level is capped (default L2), the case goes to investigation, and human review is requested for anything above.

## **78\. Other Design Corrections**

| **Area**                      | **Correction**                                                                                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Model count**               | Keep six core and three extension models in the design, but the first release uses only models whose measured value justifies their deployment cost                                        |
| **Data and feature pipeline** | Add schema-compatibility tests, event-ordering rules, late-arriving data handling, duplicate-event handling and feature-version migration tests to the shared feature library              |
| **Threat intelligence**       | Account for indicator age, source reliability, licensing and shared hosting; an IOC match alone never authorises a disruptive action                                                       |
| **LLM agents**                | Agents stay read-only for investigation and proposal generation; only a separately authorised response service executes validated actions                                                  |
| **Verification**              | Define what counts as containment, how long verification continues, how alternative attack paths are checked, and when to escalate because evidence is inconclusive                        |
| **Regulatory claims**         | Keep compliance mapping customer-specific; never describe the platform as compliant with a law or framework until obligations and implementation evidence have been independently assessed |

## **79\. Extended Evidence Labels**

Section 65 now has four statement types. The fourth, **production-validated**, means the system demonstrated acceptable performance in an authorised real-world deployment under stated conditions. A paper reference does not prove the implementation works, a benchmark score does not prove production readiness, and a passing safety test suite does not establish that all future actions will be safe.

## **80\. Traceability Matrix**

Every feature is linked from research rationale to implementation to test to release decision. The matrix is a living artefact in research/ and is a mandatory release input.

| **Feature**             | **Research rationale**                 | **Implementation decision**                   | **Test case IDs** | **Evidence report** | **Status** |
| ----------------------- | -------------------------------------- | --------------------------------------------- | ----------------- | ------------------- | ---------- |
| **Model fusion**        | Calibration and ensemble research      | Method selected after comparison (section 18) | T-FUS-01 to 06    | To be produced      | NOT TESTED |
| **Safety gate**         | Policy-as-code, safety engineering     | OPA rules (section 37)                        | T-GATE-01 to 20   | To be produced      | NOT TESTED |
| **DDoS detector**       | DDoS dataset and flow research         | M3 + statistical layer                        | T-DDOS-01 to 08   | To be produced      | NOT TESTED |
| **Agent investigation** | IR guidance, prompt-injection research | LangGraph, read-only tools                    | T-AGT-01 to 15    | To be produced      | NOT TESTED |
| **Tenant isolation**    | Zero trust, SaaS security guidance     | RLS, per-tenant keys                          | T-TEN-01 to 10    | To be produced      | NOT TESTED |

## **81\. Implementation Contract: Build Sequence and Gates**

This sequence is the actual implementation gate. A phase may not start until the previous phase's exit condition is met and recorded.

| **Phase**                                        | **Scope**                                                                                                                                   | **Exit condition**                                                                                      |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| **1\. Deterministic gateway and event pipeline** | Suricata and Zeek integration, event normalisation, explicit firewall rules, audit logs, minimal incident dashboard                         | Reproducible ingestion, tested policy enforcement, verified offline behaviour                           |
| **2\. Detection and evaluation**                 | Baseline classifier, DDoS detector, one anomaly model; labelled benign and attack scenarios; time/session-separated and external evaluation | Agreed per-class metrics, measured false-positive rate and latency, reproducible reports                |
| **3\. Fusion and investigation**                 | Fusion compared with individual models; one constrained investigation agent with evidence references and read-only tools                    | Measured improvement on agreed metrics; grounded findings; prompt-injection and permission tests passed |
| **4\. Safety-gated response**                    | Recommendation mode, then reversible low-impact actions in an isolated lab; approvals, expiry, rollback, independent verification           | All defined safety tests pass; every action auditable; failed containment escalates correctly           |
| **5\. Shadow pilot**                             | Authorised real traffic with no autonomous enforcement; compare with analyst-reviewed ground truth; measure overhead                        | Agreed thresholds and customer acceptance before any limited live response                              |

The game-theoretic engine, application and data layers, custom gateway and multi-tenant commercial platform follow only after this vertical slice has proved the central proposition and at least three paid pilots have been signed (Revision 2, gate G3).

## **82\. Mandatory Deliverables Before the Specification Is Called Final**

- A properly cited literature review with verified primary sources, findings, limitations and relevance.
- A traceability matrix (section 80) connecting each feature to its research rationale, implementation decision and test cases.
- A reproducible benchmark suite with baseline results and external-dataset evaluation.
- A security test suite for the gateway, SaaS, agents, tenant isolation and autonomous response.
- An evidence register linking every claimed capability to test results, limitations, reviewers and release status.

**Status:** until these deliverables exist, this document is a master architecture and research plan. It is not evidence that the platform works, and no feature may be described as validated on the strength of this document alone.