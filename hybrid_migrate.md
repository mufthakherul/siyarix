Phase 1 — Solidify the Foundation (1–2 months)

Goal: Make what exists actually work end-to-end reliably before building upward.



Wire up the Multi-Agent Framework — The AgentTeam, DFIRAgent, and SOCAgent classes exist but aren't connected to the execution engine. Create a coordinator agent that receives a high-level objective (e.g., "full recon + vuln scan on target.com") and dispatches sub-agents.

Close the AI feedback loop — After each ExecutionStep completes, pass the parsed findings back into the LLM planner so it can adapt subsequent steps. Currently the plan is static once generated. Implement a re-plan trigger when a step yields zero findings or fails.

Deepen E2E test coverage — Add integration tests that exercise the full planner → engine → parser → store pipeline with mocked tool output, not just unit tests on individual components.

Complete the XI (eXtended Intelligence) service — xi/service.py, xi/predictor.py, and xi/context_tracker.py exist but need connecting to the planner so predictions influence step generation.



Phase 2 — Classic Hacking Module Expansion (2–3 months)

Goal: Make Phalanx a serious offensive toolchain, not just a scan orchestrator.



Exploitation Chain Automation — Build an ExploitChain workflow type that links recon → enumeration → exploitation → post-exploitation as a sequential, parameterized campaign. Use the existing ExecutionPlan + depends_on mechanism.

Protocol-Level Attack Modules — Add tool support and parsers for: bettercap/ettercap (MITM, ARP spoofing), aircrack-ng/hostapd-wpe (wireless), impacket scripts (SMB relay, Kerberoasting). Register these in tool_registry.py.

Passive Recon Pipeline — Integrate Certificate Transparency log querying (crt.sh API), Shodan streaming, and WHOIS/BGP enrichment. Feed results directly into the Knowledge Graph as SUBDOMAIN/HOST nodes.

Custom Payload Generation — Integrate msfvenom as a registered tool with a structured payload builder: OS × arch × listener type → encoded payload. Track generated payloads in the offline store.

Social Engineering / OSINT Module — Add parsers for theHarvester, maltego (where CLI-accessible), and LinkedIn/GitHub scraper integrations. Feed into a People/Org node type in the Knowledge Graph.



Phase 3 — AI Layer Deepening (2–3 months)

Goal: Add genuine ML intelligence, not just LLM prompting.



ML-Based Anomaly Detection Engine — Build a local behavioral baseline module (using scikit-learn or a small ONNX model) that learns normal network/log patterns and flags deviations. Integrate it as an analysis step type in the execution engine.

AI-Driven Exploit Prioritization — After a scan, use CVE databases (NVD API / local mirror) + EPSS scores + network topology from the Knowledge Graph to rank exploitability. Replace the current flat findings list with a risk-scored, context-aware vulnerability report.

Adversarial AI Defense Module — Add detection for AI-targeted attacks: prompt injection in user inputs (before they reach the LLM planner), adversarial example detection for any ML classifiers in Phase 3 #10, model output hallucination scoring.

Threat Intelligence Ingestion — Ingest MISP feeds, OpenCTI, or STIX/TAXII sources into the Knowledge Graph. Automatically enrich scan findings with known threat actor TTPs from MITRE ATT&CK, creating linkages between vulnerabilities and real-world campaigns.

Autonomous Red Team Agent — Build a high-level RedTeamAgent that runs an observe–orient–decide–act (OODA) loop: observe (findings), orient (map to MITRE ATT&CK), decide (next action via LLM reasoning), act (dispatch sub-agent), loop. This is the centerpiece of the hybrid vision.



Phase 4 — Defensive AI + Deception (2 months)

Goal: The system should understand both sides — offense generates data, defense uses it.



Honeypot/Canary Token Detection — Add heuristics + ML classifier to detect when a target has deployed honeypots or canary tokens during an engagement. Warn the operator before interacting.

SOC Agent Enhancement — Upgrade the existing SOCAgent stub with a real-time log analysis pipeline: ingest syslog/Windows Event Log streams, run the anomaly detector from Phase 3, and generate automated triage tickets.

DFIR Agent Enhancement — Upgrade DFIRAgent to run actual memory forensics workflows (Volatility3 integration), timeline generation, and IOC extraction, feeding results into the offline store for reporting.

Deception Tactics Module — Implement the "attacker-facing" side: delayed/falsified responses to scanners, fake service banners, trapdoor credentials in the credential store that trigger alerts when used.



Phase 5 — Scale, Polish, and Ship (1–2 months)

Goal: Make the hybrid system deployable, observable, and community-ready.



Distributed Multi-Agent Deployment — Replace the in-process AgentTeam with a Redis/RQ-backed task queue so multiple Phalanx instances can share work. Move the SQLite offline store to PostgreSQL for the server role.

OpenTelemetry Instrumentation — Add structured traces/metrics to the execution engine, planner, and agent framework so operators can see exactly what the system is doing and why.

Web Dashboard — Build a minimal React or HTMX dashboard backed by the existing WebSocket stream.py infrastructure. Show live scan progress, Knowledge Graph visualization (using the existing visualizations/attack_graph.py), and findings heatmap.

Benchmarking & Red Team Eval Suite — Create a controlled test environment (Docker Compose with intentionally vulnerable targets like DVWA, Metasploitable) and benchmark Phalanx's detection/exploitation success rates, comparing AI-only vs. classic-only vs. hybrid modes.

Documentation & Community — Write the Hybrid Architecture guide explaining the AI+Classic philosophy, with worked examples of the OODA loop in action. Lower the contribution barrier with a "add a new tool parser" tutorial.



Summary Priority Order

Code
Phase 1 (Foundation)  →  Phase 2 (Classic depth)
         ↓                        ↓
Phase 3 (AI depth)    ←  Phase 4 (Defense/Deception)
                  ↓
            Phase 5 (Scale)

The single most impactful near-term item is Phase 1, item #2 (closing the AI feedback loop), because every phase above it depends on the planner being able to adapt based on what it learns during execution. That's the core mechanic of a true hybrid system — not just AI + classic tools running in parallel, but AI learning from the classic tool output and directing the next classic move.
