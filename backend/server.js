import express from 'express';
import cors from 'cors';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3001;

// ── Threat Intel Lookup (simulated real-world APIs) ──────────────────────────
// In production: replace with real VirusTotal/AbuseIPDB/NVD API calls

function extractIPs(text) {
  const ipRegex = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  return (text.match(ipRegex) || []).filter(ip => !ip.startsWith('192.168') && !ip.startsWith('10.') && !ip.startsWith('127.'));
}

function extractCVEs(text) {
  const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
  return text.match(cveRegex) || [];
}

function extractDomains(text) {
  const domainRegex = /\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  const domains = text.match(domainRegex) || [];
  return domains.filter(d => !d.match(/\d+\.\d+\.\d+\.\d+/) && d.includes('.'));
}

async function enrichIP(ip) {
  // 1. Try AbuseIPDB first (Better for generic IP reputation & fast)
  if (process.env.ABUSEIPDB_API_KEY) {
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
        headers: {
          'Accept': 'application/json',
          'Key': process.env.ABUSEIPDB_API_KEY
        }
      });
      if (res.ok) {
        const data = await res.json();
        const score = data.data.abuseConfidenceScore;
        return { 
          ip, 
          score, 
          type: data.data.usageType || 'unknown',
          country: data.data.countryCode || 'unknown',
          reports: data.data.totalReports,
          verdict: score > 50 ? 'malicious' : score > 20 ? 'suspicious' : 'clean',
          source: 'AbuseIPDB'
        };
      }
    } catch (e) {
      console.error(`AbuseIPDB lookup failed for ${ip}:`, e);
    }
  }

  // 2. Try VirusTotal as a fallback/alternative
  if (process.env.VIRUSTOTAL_API_KEY) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
      });
      if (res.ok) {
        const data = await res.json();
        const stats = data.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const score = Math.min((malicious * 10) + (suspicious * 5), 100); 
        return {
          ip,
          score,
          type: data.data.attributes.as_owner || 'unknown',
          country: data.data.attributes.country || 'unknown',
          reports: malicious + suspicious,
          verdict: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean',
          source: 'VirusTotal'
        };
      }
    } catch (e) {
      console.error(`VirusTotal lookup failed for ${ip}:`, e);
    }
  }

  // 3. Simulated fallback if no APIs configured or both failed
  const knownMalicious = {
    '185.220.101.47': { score: 98, type: 'TOR exit node', country: 'DE', reports: 312 },
    '91.108.4.22':    { score: 72, type: 'Telegram CDN', country: 'NL', reports: 5 },
    '194.165.16.11':  { score: 95, type: 'C2 server', country: 'RU', reports: 201 },
    '45.142.212.100': { score: 88, type: 'Botnet node', country: 'US', reports: 89 },
  };
  if (knownMalicious[ip]) {
    return { ip, ...knownMalicious[ip], verdict: 'malicious', source: 'Simulated' };
  }
  const score = Math.floor(Math.random() * 40);
  return { ip, score, type: 'unknown', country: 'unknown', reports: 0, verdict: score > 20 ? 'suspicious' : 'clean', source: 'Simulated' };
}

async function enrichCVE(cve) {
  // 1. Real NVD API lookup
  if (process.env.NVD_API_KEY) {
     try {
       // NVD API format for specific CVE
       const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, {
         headers: { 'apiKey': process.env.NVD_API_KEY }
       });
       if (res.ok) {
          const data = await res.json();
          if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            const vuln = data.vulnerabilities[0].cve;
            const metrics = vuln.metrics.cvssMetricV31?.[0] || vuln.metrics.cvssMetricV30?.[0] || vuln.metrics.cvssMetricV2?.[0];
            const cvss = metrics ? metrics.cvssData.baseScore : 'unknown';
            const desc = vuln.descriptions.find(d => d.lang === 'en')?.value || 'No English description found.';
            return { cve, cvss, desc, patch: 'Check NVD for patch details', source: 'NVD' };
          }
       }
     } catch(e) {
       console.error(`NVD API lookup failed for ${cve}:`, e);
     }
  }

  // 2. Simulated fallback if API not configured or failed
  const cveDB = {
    'CVE-2024-3094': { cvss: 10.0, desc: 'XZ Utils backdoor - supply chain compromise', patch: '5.6.2' },
    'CVE-2024-1234': { cvss: 9.8,  desc: 'Remote code execution in OpenSSH', patch: 'N/A' },
    'CVE-2023-44487': { cvss: 7.5, desc: 'HTTP/2 Rapid Reset DDoS', patch: 'vendor patch' },
    'CVE-2023-23397': { cvss: 9.8, desc: 'Microsoft Outlook privilege escalation', patch: 'MS23-023' },
  };
  if (cveDB[cve.toUpperCase()]) return { cve, ...cveDB[cve.toUpperCase()], source: 'Simulated' };
  return { cve, cvss: 'unknown', desc: 'CVE not in local database - check NVD', patch: 'unknown', source: 'Simulated' };
}

function classifyAlertType(text) {
  const t = text.toLowerCase();
  if (t.match(/brute.?force|failed.*login|ssh.*attempt|password.*spray/)) return 'brute_force';
  if (t.match(/phish|spear|bec|email.*spoof|impersonat/)) return 'phishing';
  if (t.match(/ransom|encrypt|lateral.*move|smb|wanna/)) return 'ransomware';
  if (t.match(/exfil|data.*transfer|gb.*upload|outbound.*traffic/)) return 'exfiltration';
  if (t.match(/cve-|vulnerability|exploit|backdoor|supply.chain/)) return 'vulnerability';
  if (t.match(/malware|trojan|rat|beacon|c2|command.control/)) return 'malware';
  if (t.match(/ddos|flood|amplif|reflection/)) return 'ddos';
  if (t.match(/insider|privilege.*escalat|unauthorized.*access/)) return 'insider_threat';
  return 'unknown';
}

function getMitreTactic(alertType) {
  const map = {
    brute_force:    { tactic: 'Credential Access', id: 'T1110', name: 'Brute Force' },
    phishing:       { tactic: 'Initial Access',    id: 'T1566', name: 'Phishing' },
    ransomware:     { tactic: 'Impact',            id: 'T1486', name: 'Data Encrypted for Impact' },
    exfiltration:   { tactic: 'Exfiltration',      id: 'T1048', name: 'Exfiltration Over Alt Protocol' },
    vulnerability:  { tactic: 'Execution',         id: 'T1203', name: 'Exploitation for Client Execution' },
    malware:        { tactic: 'Persistence',        id: 'T1543', name: 'Create or Modify System Process' },
    ddos:           { tactic: 'Impact',             id: 'T1498', name: 'Network Denial of Service' },
    insider_threat: { tactic: 'Privilege Escalation', id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    unknown:        { tactic: 'Unknown',            id: 'T0000', name: 'Unclassified' },
  };
  return map[alertType] || map.unknown;
}

// ── Real AI Scoring via Provider Fallbacks ───────────────────────────────────
async function callGroq(prompt) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
    },
    body: JSON.stringify({
      model: 'llama3-8b-8192',
      messages: [
        { role: 'system', content: 'You are a SOC analyst AI. Always respond with valid JSON only.' },
        { role: 'user', content: prompt }
      ],
      response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('Groq API error: ' + await res.text());
  const data = await res.json();
  return data.choices[0].message.content;
}

async function callGemini(prompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      system_instruction: { parts: { text: 'You are a SOC analyst AI. Always respond with valid JSON only.' } },
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: "application/json" }
    })
  });
  if (!res.ok) throw new Error('Gemini API error: ' + await res.text());
  const data = await res.json();
  return data.candidates[0].content.parts[0].text;
}

async function callOpenAI(prompt) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are a SOC analyst AI. Always respond with valid JSON only.' },
        { role: 'user', content: prompt }
      ],
      response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('OpenAI API error: ' + await res.text());
  const data = await res.json();
  return data.choices[0].message.content;
}

async function callOllama(prompt) {
  const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
  const res = await fetch(`${ollamaUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: process.env.OLLAMA_MODEL || 'llama3',
      messages: [
        { role: 'system', content: 'You are a SOC analyst AI. Always respond with valid JSON only.' },
        { role: 'user', content: prompt }
      ],
      stream: false,
      format: 'json'
    })
  });
  if (!res.ok) throw new Error('Ollama API error: ' + await res.text());
  const data = await res.json();
  return data.message.content;
}

async function aiScoreAlert(alertText, enrichedData) {
  const prompt = `You are an expert SOC (Security Operations Center) analyst AI. Analyze the following security alert and enrichment data, then provide a structured threat assessment.

ALERT TEXT:
${alertText}

ENRICHMENT DATA:
${JSON.stringify(enrichedData, null, 2)}

Respond ONLY with a valid JSON object in this exact format (no markdown, no explanation):
{
  "severity": "Critical|High|Medium|Low",
  "cvss_score": <number 0-10>,
  "confidence": <number 0-100>,
  "summary": "<2-3 sentence plain-English summary of the threat>",
  "immediate_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "needs_human_approval": <true if High severity, false if Critical/Medium/Low>,
  "false_positive_likelihood": "Low|Medium|High",
  "affected_systems": ["<system or scope>"],
  "recommendations": "<long-term remediation advice>"
}`;

  let rawContent;
  const errors = [];

  try {
    rawContent = await callGroq(prompt);
  } catch (e) {
    errors.push(e.message);
    try {
      rawContent = await callGemini(prompt);
    } catch (e2) {
      errors.push(e2.message);
      try {
        rawContent = await callOpenAI(prompt);
      } catch (e3) {
        errors.push(e3.message);
        try {
          rawContent = await callOllama(prompt);
        } catch (e4) {
          errors.push(e4.message);
          throw new Error('All AI providers failed: ' + errors.join(' | '));
        }
      }
    }
  }

  // Strip markdown code fences if present
  const clean = rawContent.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
  return JSON.parse(clean);
}

// ── SSE Helper ────────────────────────────────────────────────────────────────
function sendEvent(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ── Main Triage Endpoint (SSE streaming) ─────────────────────────────────────
app.post('/api/triage', async (req, res) => {
  const { alert_text, source_ip_override, analyst_name } = req.body;

  if (!alert_text || alert_text.trim().length < 10) {
    return res.status(400).json({ error: 'Alert text must be at least 10 characters.' });
  }

  // API credentials are now retrieved from the .env file.

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const ticketId = 'SOC-' + Math.floor(1000 + Math.random() * 9000);
  const startTime = Date.now();

  try {
    // ── AGENT 1: Intake & Normalise ──────────────────────────────────────────
    sendEvent(res, 'agent_start', { agent: 1, name: 'Intake + Normalise' });
    await new Promise(r => setTimeout(r, 400));

    const alertType = classifyAlertType(alert_text);
    const ips = source_ip_override ? [source_ip_override] : extractIPs(alert_text);
    const cves = extractCVEs(alert_text);
    const domains = extractDomains(alert_text);
    const mitre = getMitreTactic(alertType);

    const normalised = { alertType, ips, cves, domains, mitre, ticketId, analyst: analyst_name || 'Unknown', timestamp: new Date().toISOString() };

    sendEvent(res, 'agent_done', {
      agent: 1,
      name: 'Intake + Normalise',
      output: `Type: ${alertType.replace('_', ' ')} | IPs: ${ips.length > 0 ? ips.join(', ') : 'none'} | CVEs: ${cves.length > 0 ? cves.join(', ') : 'none'} | MITRE: ${mitre.id} — ${mitre.name}`,
      data: normalised
    });

    // ── AGENT 2: Enrich ───────────────────────────────────────────────────────
    sendEvent(res, 'agent_start', { agent: 2, name: 'Enrich + Research' });
    await new Promise(r => setTimeout(r, 500));

    const ipResults  = await Promise.all(ips.slice(0, 3).map(enrichIP));
    const cveResults = await Promise.all(cves.slice(0, 3).map(enrichCVE));

    const enriched = { ips: ipResults, cves: cveResults, domains };

    const enrichSummary = [
      ...ipResults.map(r => `${r.ip}: ${r.verdict} (score ${r.score}/100, ${r.type})`),
      ...cveResults.map(r => `${r.cve}: CVSS ${r.cvss} — ${r.desc}`),
    ].join(' | ') || 'No IPs or CVEs extracted — full text analysis proceeding';

    sendEvent(res, 'agent_done', {
      agent: 2,
      name: 'Enrich + Research',
      output: enrichSummary,
      data: enriched
    });

    // ── AGENT 3: AI Score ─────────────────────────────────────────────────────
    sendEvent(res, 'agent_start', { agent: 3, name: 'AI Score + Decide' });

    // Providers: Groq -> Gemini -> OpenAI -> Ollama
    let scoring;
    try {
      scoring = await aiScoreAlert(alert_text, { ...normalised, ...enriched });
    } catch (e) {
      // Fallback scoring if APIs fail
      const highIpScore = ipResults.some(r => r.score > 70);
      const highCvss = cveResults.some(r => r.cvss >= 9.0);
      scoring = {
        severity: highIpScore || highCvss ? 'High' : alertType === 'ransomware' ? 'Critical' : 'Medium',
        cvss_score: highCvss ? 9.5 : 6.5,
        confidence: 70,
        summary: 'AI scoring unavailable — heuristic fallback applied. Review enrichment data manually.',
        immediate_actions: ['Investigate source IPs', 'Review affected systems', 'Escalate to senior analyst'],
        needs_human_approval: true,
        false_positive_likelihood: 'Medium',
        affected_systems: ['Unknown — manual review required'],
        recommendations: 'Manual triage recommended due to AI scoring unavailability.'
      };
    }

    sendEvent(res, 'agent_done', {
      agent: 3,
      name: 'AI Score + Decide',
      output: `Severity: ${scoring.severity} | CVSS: ${scoring.cvss_score} | Confidence: ${scoring.confidence}% | FP likelihood: ${scoring.false_positive_likelihood}`,
      data: scoring
    });

    // ── AGENT 4: Action ───────────────────────────────────────────────────────
    sendEvent(res, 'agent_start', { agent: 4, name: 'Action Agent' });
    await new Promise(r => setTimeout(r, 400));

    if (scoring.needs_human_approval) {
      sendEvent(res, 'approval_required', {
        agent: 4,
        name: 'Action Agent',
        proposed_actions: scoring.immediate_actions,
        scoring,
        ticketId
      });
      // Keep connection alive — wait for approval via separate endpoint
      // The frontend will POST to /api/approve/:ticketId
      // Store pending in memory
      pendingApprovals[ticketId] = { res, scoring, normalised, enriched, startTime, ticketId, analyst: analyst_name };
      return; // Don't close response yet
    }

    // Auto-action for Critical/Medium/Low
    const actionsText = scoring.immediate_actions.join(' | ');
    sendEvent(res, 'agent_done', {
      agent: 4,
      name: 'Action Agent',
      output: `Auto-executed: ${actionsText} | Ticket ${ticketId} created.`,
      data: { actions: scoring.immediate_actions, auto: true, ticketId }
    });

    // ── AGENT 5: Audit ────────────────────────────────────────────────────────
    await finishWithAudit(res, { scoring, normalised, enriched, startTime, ticketId, analyst: analyst_name, approved: null });

  } catch (err) {
    sendEvent(res, 'error', { message: err.message });
    res.end();
  }
});

// ── Pending approvals store (in-memory) ───────────────────────────────────────
const pendingApprovals = {};

app.post('/api/approve/:ticketId', async (req, res) => {
  const { ticketId } = req.params;
  const { decision, analyst_note } = req.body; // decision: 'approve' | 'reject'

  const pending = pendingApprovals[ticketId];
  if (!pending) return res.status(404).json({ error: 'No pending approval for ' + ticketId });

  const { res: sseRes, scoring, normalised, enriched, startTime, analyst } = pending;
  delete pendingApprovals[ticketId];

  if (decision === 'approve') {
    sendEvent(sseRes, 'agent_done', {
      agent: 4,
      name: 'Action Agent',
      output: `APPROVED by analyst. Executing: ${scoring.immediate_actions.join(' | ')} | Note: ${analyst_note || 'none'}`,
      data: { actions: scoring.immediate_actions, auto: false, approved: true, ticketId }
    });
  } else {
    sendEvent(sseRes, 'agent_done', {
      agent: 4,
      name: 'Action Agent',
      output: `REJECTED by analyst. Escalated to IR team. Note: ${analyst_note || 'none'}`,
      data: { actions: ['Escalated to senior IR analyst'], auto: false, approved: false, ticketId }
    });
  }

  await finishWithAudit(sseRes, { scoring, normalised, enriched, startTime, ticketId, analyst, approved: decision });
  res.json({ ok: true });
});

async function finishWithAudit(res, { scoring, normalised, enriched, startTime, ticketId, analyst, approved }) {
  sendEvent(res, 'agent_start', { agent: 5, name: 'Audit + Report' });
  await new Promise(r => setTimeout(r, 300));

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
  const auditLog = {
    ticketId,
    timestamp: new Date().toISOString(),
    analyst: analyst || 'system',
    elapsed_seconds: parseFloat(elapsed),
    alert_type: normalised.alertType,
    severity: scoring.severity,
    cvss: scoring.cvss_score,
    confidence: scoring.confidence,
    mitre: normalised.mitre,
    ips_checked: enriched.ips.length,
    cves_checked: enriched.cves.length,
    actions_taken: scoring.immediate_actions,
    human_approved: approved,
    recommendations: scoring.recommendations
  };

  sendEvent(res, 'agent_done', {
    agent: 5,
    name: 'Audit + Report',
    output: `Ticket ${ticketId} — ${scoring.severity} — ${elapsed}s total — ${scoring.immediate_actions.length} actions logged — audit trail complete.`,
    data: auditLog
  });

  sendEvent(res, 'complete', {
    ticketId,
    elapsed,
    severity: scoring.severity,
    summary: scoring.summary,
    auditLog
  });

  res.end();
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`SOC Triage Backend running on http://localhost:${PORT}`));
