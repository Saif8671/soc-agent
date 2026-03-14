import React, { useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";

const API = "http://localhost:3001";

const TEMPLATES = {
  bruteforce: {
    type: "Brute Force",
    ip: "185.220.101.47",
    target: "prod-db-01",
    timestamp: new Date().toISOString(),
    log: "847 failed SSH login attempts detected from IP 185.220.101.47 targeting prod-db-01 within 3 minutes. Attempts using common usernames: root, admin, ubuntu. Protocol: SSH port 22.",
  },
  cve: {
    type: "Vulnerability / Exploit",
    ip: "Unknown",
    target: "build-01, build-02, build-03",
    timestamp: new Date().toISOString(),
    log: "CVE-2024-3094 detected in liblzma version 5.6.0 installed on 3 build servers. This is the XZ Utils backdoor with CVSS 10.0. Patch 5.6.2 is available.",
  },
  phishing: {
    type: "Phishing / BEC",
    ip: "Unknown",
    target: "finance-team-inbox",
    timestamp: new Date().toISOString(),
    log: "Spear phishing email received by finance team (4 recipients). Sender spoofing CEO: ceo@acme-corp.net (real domain: acme.com). Email contains malicious link. SPF/DKIM failed. Requesting urgent wire transfer of $47,000.",
  },
  exfil: {
    type: "Data Exfiltration",
    ip: "91.108.4.22",
    target: "dev-laptop-22",
    timestamp: new Date().toISOString(),
    log: "4.2 GB of data transferred from dev-laptop-22 to external IP 91.108.4.22 over 14 minutes. No prior baseline for this volume. User: saif@company.com. Transfer via HTTPS port 443.",
  },
  ransomware: {
    type: "Ransomware Lateral Movement",
    ip: "192.168.1.15",
    target: "FINANCE-PC-04",
    timestamp: new Date().toISOString(),
    log: "Ransomware precursor activity detected. SMB lateral movement across 6 hosts originating from FINANCE-PC-04. Encrypted file extensions appearing (.locked). Matches LockBit 3.0 TTPs. Admin shares being accessed.",
  },
  insider: {
    type: "Insider Threat",
    ip: "192.168.1.112",
    target: "customer-db-read-replica",
    timestamp: new Date().toISOString(),
    log: "Privileged user jdoe@company.com accessed 3,400 customer records outside business hours (02:00-04:30 UTC). User is on PIP and has resignation pending. Data downloaded to personal USB drive. DLP alert triggered.",
  },
};

const TEMPLATE_LABELS = {
  bruteforce: "SSH Brute Force",
  cve: "CVE / Vuln",
  phishing: "Phishing BEC",
  exfil: "Data Exfil",
  ransomware: "Ransomware",
  insider: "Insider Threat",
};

const makeEmptyAgents = () =>
  Array.from({ length: 5 }, () => ({
    state: "",
    out: "",
    timer: "",
  }));

const makeEmptyPipes = () => Array.from({ length: 6 }, () => "");

function App() {
  const [alertType, setAlertType] = useState("");
  const [sourceIP, setSourceIP] = useState("");
  const [targetSystem, setTargetSystem] = useState("");
  const [alertTimestamp, setAlertTimestamp] = useState("");
  const [rawLogData, setRawLogData] = useState("");
  const [analystNote, setAnalystNote] = useState("");
  const [activeTemplate, setActiveTemplate] = useState("");

  const [running, setRunning] = useState(false);
  const runningRef = useRef(false);
  const startTimeRef = useRef(0);
  const currentTicketIdRef = useRef(null);

  const [statusText, setStatusText] = useState("SYSTEM READY");
  const [statusDotClass, setStatusDotClass] = useState("pulse");

  const [logEntries, setLogEntries] = useState([]);
  const logBoxRef = useRef(null);

  const [pipeStates, setPipeStates] = useState(makeEmptyPipes);
  const [agentStates, setAgentStates] = useState(makeEmptyAgents);

  const [approvalVisible, setApprovalVisible] = useState(false);
  const [approvalActions, setApprovalActions] = useState([]);
  const approvalVisibleRef = useRef(false);

  const [verdictVisible, setVerdictVisible] = useState(false);
  const [verdict, setVerdict] = useState(null);

  const [metrics, setMetrics] = useState({ total: 0, crit: 0, times: [], auto: 0 });

  const avgTime = useMemo(() => {
    if (!metrics.times.length) return "-";
    const avg = metrics.times.reduce((a, b) => a + b, 0) / metrics.times.length;
    return avg.toFixed(1) + "s";
  }, [metrics]);

  useEffect(() => {
    if (!logBoxRef.current) return;
    logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
  }, [logEntries.length]);

  useEffect(() => {
    approvalVisibleRef.current = approvalVisible;
  }, [approvalVisible]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const r = await fetch(`${API}/api/health`);
        if (!mounted) return;
        if (r.ok) {
          setStatusText("BACKEND CONNECTED");
          setTimeout(() => {
            if (mounted) setStatusText("SYSTEM READY");
          }, 2000);
        }
      } catch {
        if (!mounted) return;
        setStatusText("BACKEND OFFLINE");
        setStatusDotClass("pulse offline");
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  const ts = () =>
    new Date().toLocaleTimeString("en-US", { hour12: false });

  const addLog = (tag, msg, color = "var(--muted2)") => {
    setLogEntries((prev) => [...prev, { ts: ts(), tag, msg, color }]);
  };

  const setPipeNode = (n, state) => {
    setPipeStates((prev) => {
      const next = [...prev];
      next[n] = state || "";
      return next;
    });
  };

  const setAgent = (n, state, out, timer) => {
    setAgentStates((prev) => {
      const next = [...prev];
      const idx = n - 1;
      const cur = next[idx] || { state: "", out: "", timer: "" };
      next[idx] = {
        state: state ?? cur.state,
        out: out !== undefined ? out : cur.out,
        timer: timer !== undefined ? timer : cur.timer,
      };
      return next;
    });
  };

  const resetUI = () => {
    setAgentStates(makeEmptyAgents());
    setPipeStates(makeEmptyPipes());
    setLogEntries([]);
    setVerdictVisible(false);
    setVerdict(null);
    setApprovalVisible(false);
    setApprovalActions([]);
    setAnalystNote("");
    setActiveTemplate("");
  };

  const elapsed = () =>
    ((Date.now() - startTimeRef.current) / 1000).toFixed(1) + "s";

  const badgeClass = (sev) => {
    if (sev === "Critical") return "b-crit";
    if (sev === "High") return "b-high";
    if (sev === "Medium") return "b-med";
    return "b-low";
  };

  const finishRun = () => {
    runningRef.current = false;
    setRunning(false);
    setStatusText("SYSTEM READY");
  };

  const handleEvent = (event, d) => {
    const n = d.agent;

    if (event === "agent_start") {
      setPipeNode(n, "active");
      setAgent(n, "running");
      addLog(`A0${n}`, `${d.name}: running...`, "var(--blue)");
      return;
    }

    if (event === "agent_done") {
      setPipeNode(n, "done");
      setAgent(n, "done", d.output, elapsed());
      addLog(`A0${n}`, d.output, "var(--blue)");
      return;
    }

    if (event === "approval_required") {
      setPipeNode(n, "active");
      setAgent(n, "waiting", "Awaiting analyst approval...", elapsed());
      currentTicketIdRef.current = d.ticketId;
      addLog("A04", "Human gate triggered - severity HIGH", "var(--amber)");

      const actions = d.proposed_actions || [];
      setApprovalActions(actions);
      setApprovalVisible(true);
      setStatusText("AWAITING APPROVAL");
      return;
    }

    if (event === "complete") {
      const sev = d.severity;
      setMetrics((prev) => {
        const times = [...prev.times, parseFloat(d.elapsed)];
        return {
          total: prev.total + 1,
          crit: prev.crit + (sev === "Critical" ? 1 : 0),
          times,
          auto: prev.auto + (d.auditLog?.human_approved ? 0 : 1),
        };
      });

      addLog(
        "SYS",
        `Complete - ${d.elapsed}s - Ticket ${d.ticketId}`,
        "var(--green)"
      );
      setVerdict(d);
      setVerdictVisible(true);
      setApprovalVisible(false);
      finishRun();
    }

    if (event === "error") {
      addLog("ERR", d.message, "var(--red)");
      finishRun();
    }
  };

  const handleTemplateClick = (key) => {
    const t = TEMPLATES[key];
    setAlertType(t.type);
    setSourceIP(t.ip);
    setTargetSystem(t.target);
    setAlertTimestamp(t.timestamp);
    setRawLogData(t.log);
    setActiveTemplate(key);
  };

  const triggerTriage = async () => {
    if (runningRef.current) return;

    const trimmedLog = rawLogData.trim();
    const trimmedSource = sourceIP.trim();

    if (!trimmedLog || trimmedLog.length < 10) {
      alert("Please enter the Raw Log Data (min 10 characters).");
      return;
    }

    const combinedText = `
Alert Type: ${alertType.trim() || 'Not specified'}
Source IP Address: ${trimmedSource || 'Not specified'}
Target System/Hostname: ${targetSystem.trim() || 'Not specified'}
Alert Timestamp: ${alertTimestamp.trim() || 'Not specified'}

Raw Log Data:
${trimmedLog}
    `.trim();

    runningRef.current = true;
    setRunning(true);
    startTimeRef.current = Date.now();
    currentTicketIdRef.current = null;
    resetUI();

    setStatusText("AGENT ACTIVE");
    setPipeNode(0, "active");
    addLog("SYS", "Triage initiated", "var(--green)");

    try {
      const response = await fetch(`${API}/api/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_text: combinedText,
          source_ip_override: trimmedSource || undefined,
          analyst_name: "SOC Analyst",
        }),
      });

      if (!response.ok) {
        let err;
        try {
          err = await response.json();
        } catch {
          err = {};
        }
        throw new Error(err.error || "Backend error");
      }

      setPipeNode(0, "done");
      addLog("SYS", "Connected to agent pipeline - streaming...", "var(--green)");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const events = buffer.split("\n\n");
        buffer = events.pop();

        for (const chunk of events) {
          if (!chunk.trim()) continue;
          const lines = chunk.split("\n");
          let event = "";
          let data = "";
          for (const line of lines) {
            if (line.startsWith("event: ")) event = line.slice(7);
            if (line.startsWith("data: ")) data = line.slice(6);
          }
          if (!event || !data) continue;

          let d;
          try {
            d = JSON.parse(data);
          } catch {
            continue;
          }

          handleEvent(event, d);
        }
      }
    } catch (err) {
      addLog("ERR", err.message, "var(--red)");
      [1, 2, 3, 4, 5].forEach((n) => {
        setAgent(n, "error", "Connection error", elapsed());
      });
    } finally {
      if (!approvalVisibleRef.current) {
        finishRun();
      }
    }
  };

  const submitApproval = async (decision) => {
    const ticketId = currentTicketIdRef.current;
    if (!ticketId) return;
    const note = analystNote.trim();

    setApprovalVisible(false);
    addLog(
      "HUM",
      `Analyst ${decision === "approve" ? "APPROVED" : "REJECTED"} - ${
        note || "no note"
      }`,
      decision === "approve" ? "var(--green)" : "var(--red)"
    );

    try {
      await fetch(`${API}/api/approve/${ticketId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, analyst_note: note }),
      });
    } catch (e) {
      addLog("ERR", "Could not reach backend for approval: " + e.message, "var(--red)");
      finishRun();
    }
  };

  const verdictLog = verdict?.auditLog || {};

  return (
    <div className="app">
      <nav className="topbar">
        <div className="topbar-left">
          <div className="logo">SOC <em>Triage</em> Agent</div>
        </div>
        <div className="topbar-right">
          <div className="status-pill">
            <div className={statusDotClass} id="statusDot"></div>
            <span id="statusText">{statusText}</span>
          </div>
        </div>
      </nav>

      <div className="main">
        <aside className="sidebar">
          <div className="sidebar-section" style={{ paddingBottom: 16 }}>
            <div className="field">
              <label className="field-label" style={{color: 'var(--cyan)'}}>Quick insert templates</label>
              <div className="tag-row">
                {Object.keys(TEMPLATE_LABELS).map((key) => (
                  <span
                    key={key}
                    className={`tag-chip${activeTemplate === key ? " active" : ""}`}
                    onClick={() => handleTemplateClick(key)}
                  >
                    {TEMPLATE_LABELS[key]}
                  </span>
                ))}
              </div>
            </div>

            <div className="row">
              <div>
                <label className="field-label">Alert Type</label>
                <input
                  type="text" placeholder="e.g. Brute Force"
                  value={alertType} onChange={(e) => setAlertType(e.target.value)}
                />
              </div>
              <div>
                <label className="field-label">Alert Timestamp</label>
                <input
                  type="text" placeholder="ISO 8601 / UTC"
                  value={alertTimestamp} onChange={(e) => setAlertTimestamp(e.target.value)}
                />
              </div>
            </div>

            <div className="row">
              <div>
                <label className="field-label">Source IP Address</label>
                <input
                  type="text" placeholder="e.g. 185.220.101.47"
                  value={sourceIP} onChange={(e) => setSourceIP(e.target.value)}
                />
              </div>
              <div>
                <label className="field-label">Target System/Hostname</label>
                <input
                  type="text" placeholder="e.g. prod-db-01"
                  value={targetSystem} onChange={(e) => setTargetSystem(e.target.value)}
                />
              </div>
            </div>

            <div className="field">
              <label className="field-label">Raw Log Data</label>
              <textarea
                rows={5}
                placeholder="Paste raw logs, firewall blocks, email headers here..."
                value={rawLogData}
                onChange={(e) => setRawLogData(e.target.value)}
              ></textarea>
            </div>

            <button
              className="trigger-btn"
              id="triggerBtn"
              onClick={triggerTriage}
              disabled={running}
            >
              {running ? "[ Processing... ]" : "[ Run SOC triage agent ]"}
            </button>
          </div>

          <div className="sidebar-section" style={{ paddingBottom: 16, flex: 1 }}>
            <div className="agents-title">Agent pipeline</div>
            {agentStates.map((agent, idx) => (
              <div key={idx} className={`agent-card${agent.state ? ` ${agent.state}` : ""}`}>
                <div className={`indicator${agent.state ? ` ${agent.state}` : ""}`}></div>
                <div className="agent-info">
                  <div className="agent-name">
                    {String(idx + 1).padStart(2, "0")} - {[
                      "Intake + Normalise",
                      "Enrich + Research",
                      "AI Score + Decide",
                      "Action Agent",
                      "Audit + Report",
                    ][idx]}
                  </div>
                  <div className={`agent-out${agent.out ? " show" : ""}`}>{agent.out}</div>
                </div>
                <div className="agent-timer">{agent.timer}</div>
              </div>
            ))}
          </div>
        </aside>

        <main className="right-panel">
          <div className="metrics">
            <div className="metric">
              <div className="metric-label">Processed</div>
              <div className="metric-val g">{metrics.total}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Critical</div>
              <div className="metric-val r">{metrics.crit}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Avg time</div>
              <div className="metric-val a">{avgTime}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Auto-resolved</div>
              <div className="metric-val">{metrics.auto}</div>
            </div>
          </div>

          <div className="pipeline-bar">
            {[
              { label: "Trigger", sub: "input" },
              { label: "Intake", sub: "parse" },
              { label: "Enrich", sub: "VT / MITRE" },
              { label: "AI Score", sub: "LLM" },
              { label: "Action", sub: "ticket / block" },
              { label: "Audit", sub: "log trail" },
            ].map((node, idx) => (
              <div className="pipe-node" key={node.label}>
                <div
                  className={`pipe-box${pipeStates[idx] ? ` ${pipeStates[idx]}` : ""}`}
                >
                  {node.label}
                </div>
                <div className="pipe-sub">{node.sub}</div>
              </div>
            )).reduce((acc, el, idx) => {
              acc.push(el);
              if (idx < 5) acc.push(<div className="pipe-arrow" key={`arrow-${idx}`} />);
              return acc;
            }, [])}
          </div>

          <div className="log-wrap">
            <div className="log-header">
              <div className="log-title">Live audit log</div>
              <div className="log-count">{logEntries.length} entries</div>
            </div>
            <div id="logbox" ref={logBoxRef}>
              {logEntries.length === 0 ? (
                <div className="log-empty">Awaiting trigger...</div>
              ) : (
                logEntries.map((line, idx) => (
                  <div key={idx} className="log-line">
                    <span className="log-ts">{line.ts}</span>
                    <span className="log-tag" style={{ color: line.color }}>
                      [{line.tag}]
                    </span>
                    <span className="log-msg">{line.msg}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="approval-wrap" style={{ display: approvalVisible ? "block" : "none" }}>
            <div className="approval-header">
              <span className="approval-badge">[ Human gate ]</span>
              <span className="approval-title">Analyst approval required - High severity</span>
            </div>
            <div className="approval-proposed">
              <div className="label">Proposed actions</div>
              <div className="actions-list">
                {approvalActions.map((a, idx) => (
                  <div className="action-item" key={`${a}-${idx}`}>
                    <span className="action-bullet">&gt;</span>
                    <span>{a}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="field">
              <label className="field-label">Analyst note (optional)</label>
              <input
                type="text"
                id="analystNote"
                placeholder="Add context or reasoning..."
                className="note-field"
                value={analystNote}
                onChange={(e) => setAnalystNote(e.target.value)}
              />
            </div>
            <div className="approval-btns">
              <button className="btn-approve" onClick={() => submitApproval("approve")}>
                [ Approve + Execute ]
              </button>
              <button className="btn-reject" onClick={() => submitApproval("reject")}>
                [ Reject + Escalate ]
              </button>
            </div>
          </div>

          <div className="verdict-wrap" style={{ display: verdictVisible ? "block" : "none" }}>
            <div className="verdict-title">Assessment complete</div>
            <div className="verdict-grid">
              <div className="v-card">
                <div className="v-label">Severity</div>
                <div className="v-val">
                  <span className={`badge ${badgeClass(verdict?.severity)}`}>
                    {verdict?.severity || "-"}
                  </span>
                </div>
              </div>
              <div className="v-card">
                <div className="v-label">CVSS / Confidence</div>
                <div className="v-val" style={{ color: "var(--amber)" }}>
                  {verdictLog.cvss || "-"} / {verdictLog.confidence || "-"}%
                </div>
              </div>
              <div className="v-card">
                <div className="v-label">MITRE tactic</div>
                <div className="v-val" style={{ fontSize: 11, color: "var(--purple)" }}>
                  {(verdictLog.mitre?.id || "-") + " - " + (verdictLog.mitre?.name || "unknown")}
                </div>
              </div>
              <div className="v-card">
                <div className="v-label">Ticket</div>
                <div className="v-val" style={{ color: "var(--blue)" }}>
                  {verdictLog.ticketId || "-"}
                </div>
              </div>
              <div className="v-card v-full">
                <div className="v-label">AI Summary</div>
                <div className="v-text">{verdict?.summary || "-"}</div>
              </div>
              <div className="v-card v-full">
                <div className="v-label">Recommended actions</div>
                <div className="actions-list">
                  {(verdictLog.actions_taken || []).map((a, idx) => (
                    <div className="action-item" key={`${a}-${idx}`}>
                      <span className="action-bullet">&gt;</span>
                      <span>{a}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="v-card v-full">
                <div className="v-label">Long-term recommendations</div>
                <div className="v-text">{verdictLog.recommendations || "-"}</div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
