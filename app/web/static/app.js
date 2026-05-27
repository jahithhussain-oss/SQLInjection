/* ── Tab switching ── */
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "history") loadHistory();
  });
});

/* ── Severity helpers ── */
const SEV_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
function sevBadge(s) {
  return `<span class="badge badge-${s}">${s}</span>`;
}
function sevColor(s) {
  return { LOW: "#58a6ff", MEDIUM: "#d29922", HIGH: "#f0883e", CRITICAL: "#ff4444", NONE: "#3fb950" }[s] || "#8b949e";
}

/* ══════════════════════════════════════════════════════════
   HEADER ROWS (API tab)
══════════════════════════════════════════════════════════ */
let _headerCount = 0;

function addHeaderRow(name = "", value = "") {
  const id = ++_headerCount;
  const container = document.getElementById("header-rows");

  // Remove the empty-state message if present
  const msg = container.querySelector(".no-headers-msg");
  if (msg) msg.remove();

  const row = document.createElement("div");
  row.className = "header-row";
  row.id = `hrow-${id}`;
  row.innerHTML = `
    <input type="text"  class="hkey"   placeholder="Header name"  value="${esc(name)}" />
    <input type="text"  class="hval"   placeholder="Header value" value="${esc(value)}" />
    <button class="btn-remove" onclick="removeHeaderRow(${id})">✕</button>`;
  container.appendChild(row);

  // Focus the name field if it's empty
  if (!name) row.querySelector(".hkey").focus();
}

function addPreset(name, value) {
  // If a row with this header name already exists, focus its value field instead
  const rows = document.querySelectorAll("#header-rows .header-row");
  for (const row of rows) {
    const keyInput = row.querySelector(".hkey");
    if (keyInput && keyInput.value.toLowerCase() === name.toLowerCase()) {
      keyInput.nextElementSibling.focus();
      return;
    }
  }
  addHeaderRow(name, value);
  // Auto-focus the value field of the newly added row
  const rows2 = document.querySelectorAll("#header-rows .header-row");
  const last = rows2[rows2.length - 1];
  if (last) last.querySelector(".hval").focus();
}

function removeHeaderRow(id) {
  const row = document.getElementById(`hrow-${id}`);
  if (row) row.remove();
  // Show empty-state message if no rows left
  const container = document.getElementById("header-rows");
  if (!container.querySelector(".header-row")) {
    container.innerHTML = `<div class="no-headers-msg">No custom headers added. Use the presets or "+ Add Header" above.</div>`;
  }
}

function collectHeaders() {
  const headers = {};
  document.querySelectorAll("#header-rows .header-row").forEach(row => {
    const key   = (row.querySelector(".hkey")?.value || "").trim();
    const value = (row.querySelector(".hval")?.value || "").trim();
    if (key) headers[key] = value;
  });
  return headers;
}

/* ══════════════════════════════════════════════════════════
   WEB / API SCAN
══════════════════════════════════════════════════════════ */
const _polls = {};   // scan_id -> intervalId

async function startScan(type) {
  const btn = document.getElementById(`${type}-scan-btn`);
  const resultsDiv = document.getElementById(`${type}-results`);

  let url, body;
  if (type === "web") {
    url = document.getElementById("web-url").value.trim();
    if (!url) { alert("Please enter a target URL."); return; }
    body = {
      scan_type: "web",
      url,
      max_pages: parseInt(document.getElementById("web-maxpages").value) || 30,
      delay: parseFloat(document.getElementById("web-delay").value) || 0.3,
    };
  } else {
    url = document.getElementById("api-url").value.trim();
    const params = document.getElementById("api-params").value.trim();
    if (!url)    { alert("Please enter an API URL."); return; }
    if (!params) { alert("Please enter parameters."); return; }
    body = {
      scan_type: "api",
      url,
      params,
      method: document.getElementById("api-method").value,
      use_json: document.getElementById("api-format").value === "json",
      headers: collectHeaders(),
      delay: parseFloat(document.getElementById("api-delay").value) || 0.3,
    };
  }

  btn.disabled = true;
  btn.textContent = "⏳ Scanning…";

  const res = await fetch("/api/scan/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const { scan_id, error } = await res.json();
  if (error) { alert("Error: " + error); btn.disabled = false; btn.textContent = "▶ Start Scan"; return; }

  resultsDiv.innerHTML = renderScanCard(scan_id, url, type, [], "running", null, [], []);
  _polls[scan_id] = setInterval(() => pollScan(scan_id, type, btn), 2000);
}

async function pollScan(scan_id, type, btn) {
  const res = await fetch(`/api/scan/status/${scan_id}`);
  const data = await res.json();
  const resultsDiv = document.getElementById(`${type}-results`);

  resultsDiv.innerHTML = renderScanCard(
    scan_id, data.url, type, data.logs || [],
    data.status, data.summary, data.vulnerabilities || [],
    data.custom_headers || []
  );

  if (data.status !== "running") {
    clearInterval(_polls[scan_id]);
    btn.disabled = false;
    btn.textContent = "▶ Start Scan";
  }
}

function renderScanCard(scan_id, url, type, logs, status, summary, vulns, customHeaders) {
  const statusHtml = `<span class="status-pill status-${status}">${
    status === "running" ? '<span class="spinner"></span> Scanning' :
    status === "done"    ? "✓ Done" : "✗ Error"
  }</span>`;

  const headersHtml = (customHeaders && customHeaders.length)
    ? `<div style="margin-bottom:10px;font-size:.8rem;color:var(--muted)">
         🔑 Custom headers sent: ${customHeaders.map(h => `<code style="background:#1c2128;padding:1px 6px;border-radius:3px;margin:0 2px">${esc(h)}</code>`).join(" ")}
       </div>`
    : "";

  let summaryHtml = "";
  if (summary) {
    const total = summary.total_vulnerabilities;
    const sb = summary.severity_breakdown || {};
    summaryHtml = `
      <div class="summary-bar">
        <div class="summary-stat ${total > 0 ? "vuln" : "safe"}">
          <div class="num">${total}</div>
          <div class="lbl">Vulnerabilities</div>
        </div>
        <div class="summary-stat">
          <div class="num">${summary.scanned_urls}</div>
          <div class="lbl">URLs Scanned</div>
        </div>
        ${["CRITICAL","HIGH","MEDIUM","LOW"].map(s =>
          sb[s] ? `<div class="summary-stat">
            <div class="num" style="color:${sevColor(s)}">${sb[s]}</div>
            <div class="lbl">${s}</div>
          </div>` : ""
        ).join("")}
      </div>`;
  }

  let vulnHtml = "";
  if (vulns && vulns.length > 0) {
    const rows = vulns.map((v, i) => `
      <tr>
        <td>${i + 1}</td>
        <td>${sevBadge(v.severity)}</td>
        <td>${v.type}</td>
        <td><code style="font-size:.78rem">${esc(v.parameter)}</code></td>
        <td><code style="font-size:.78rem;color:#f0883e">${esc(v.payload)}</code></td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(v.url)}">${esc(v.url)}</td>
        <td><button class="btn-link" onclick='showVuln(${JSON.stringify(v)})'>Details</button></td>
      </tr>`).join("");
    vulnHtml = `
      <table class="vuln-table">
        <thead><tr>
          <th>#</th><th>Severity</th><th>Type</th>
          <th>Parameter</th><th>Payload</th><th>URL</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } else if (status === "done") {
    vulnHtml = `<div class="empty-state">✅ No SQL injection vulnerabilities detected.</div>`;
  }

  const logLines = (logs || []).slice(-60).map(l => {
    const cls = l.includes("[WARN]") ? "log-warn" : l.includes("[ERROR]") ? "log-err" : l.includes("[DONE]") ? "log-done" : "";
    return `<div class="${cls}">${esc(l)}</div>`;
  }).join("");

  return `
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div>
          <strong style="font-size:.85rem;color:var(--muted)">Scan ID:</strong>
          <code style="font-size:.82rem">${scan_id}</code>
        </div>
        ${statusHtml}
      </div>
      ${headersHtml}
      ${summaryHtml}
      ${vulnHtml}
      <div class="log-box" id="log-${scan_id}">${logLines}</div>
    </div>`;
}

/* ══════════════════════════════════════════════════════════
   INPUT ANALYZER
══════════════════════════════════════════════════════════ */
async function analyzeInput() {
  const text = document.getElementById("input-text").value.trim();
  if (!text) { alert("Please enter some text to analyse."); return; }

  const res = await fetch("/api/analyze-input", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }

  const div = document.getElementById("input-results");

  if (!data.is_suspicious) {
    div.innerHTML = `
      <div class="card" style="border-left:4px solid var(--green)">
        <div style="display:flex;align-items:center;gap:10px">
          <span style="font-size:1.5rem">✅</span>
          <div>
            <strong>Input appears clean</strong>
            <p style="color:var(--muted);font-size:.83rem;margin-top:4px">No SQL injection patterns detected.</p>
          </div>
        </div>
      </div>`;
    return;
  }

  const cards = data.findings.map(f => `
    <div class="finding-card ${f.severity}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        ${sevBadge(f.severity)}
        <h4>${esc(f.rule)}</h4>
      </div>
      <p>${esc(f.description)}</p>
      <p style="margin-top:6px">
        Matched: <code>${esc(f.matched)}</code>
        &nbsp;·&nbsp; Position: <code>${f.position}</code>
      </p>
    </div>`).join("");

  div.innerHTML = `
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
        <span style="font-size:1.5rem">⚠️</span>
        <div>
          <strong>${data.findings.length} pattern(s) detected</strong>
          <p style="color:var(--muted);font-size:.83rem;margin-top:2px">
            Max severity: ${sevBadge(data.max_severity)}
          </p>
        </div>
      </div>
      ${cards}
    </div>`;
}

/* ══════════════════════════════════════════════════════════
   SCAN HISTORY
══════════════════════════════════════════════════════════ */
async function loadHistory() {
  const res = await fetch("/api/scans");
  const items = await res.json();
  const div = document.getElementById("history-list");

  if (!items.length) {
    div.innerHTML = `<div class="empty-state">No scans yet. Run a web or API scan first.</div>`;
    return;
  }

  div.innerHTML = items.map(s => `
    <div class="history-item">
      <div>
        <div class="hi-url">${esc(s.url)}</div>
        <div class="hi-meta">
          ${s.scan_type.toUpperCase()} &nbsp;·&nbsp; Started: ${s.started_at}
          &nbsp;·&nbsp; ID: <code>${s.scan_id}</code>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
        ${s.vuln_count > 0
          ? `<span style="color:var(--red);font-weight:700">${s.vuln_count} vuln${s.vuln_count > 1 ? "s" : ""}</span>`
          : `<span style="color:var(--green)">Clean</span>`}
        <span class="status-pill status-${s.status}">${s.status}</span>
        <button class="btn-secondary" onclick="viewScanDetail('${s.scan_id}','${s.scan_type}')">View</button>
      </div>
    </div>`).join("");
}

async function viewScanDetail(scan_id, type) {
  const res = await fetch(`/api/scan/status/${scan_id}`);
  const data = await res.json();
  const content = document.getElementById("modal-content");

  content.innerHTML = renderScanCard(
    scan_id, data.url, type, data.logs || [],
    data.status, data.summary, data.vulnerabilities || [],
    data.custom_headers || []
  );
  document.getElementById("modal-overlay").classList.remove("hidden");
}

/* ══════════════════════════════════════════════════════════
   VULN DETAIL MODAL
══════════════════════════════════════════════════════════ */
function showVuln(v) {
  const content = document.getElementById("modal-content");
  content.innerHTML = `
    <h3 style="margin-bottom:16px">Vulnerability Detail</h3>
    <table style="width:100%;border-collapse:collapse;font-size:.88rem">
      ${[
        ["Type",      v.type],
        ["Severity",  sevBadge(v.severity)],
        ["URL",       `<code style="word-break:break-all">${esc(v.url)}</code>`],
        ["Method",    v.method],
        ["Parameter", `<code>${esc(v.parameter)}</code>`],
        ["Payload",   `<code style="color:#f0883e">${esc(v.payload)}</code>`],
        ["Evidence",  `<span style="color:var(--muted)">${esc(v.evidence)}</span>`],
      ].map(([k, val]) => `
        <tr>
          <td style="padding:8px 12px;color:var(--muted);white-space:nowrap;width:110px;border-bottom:1px solid var(--border)">${k}</td>
          <td style="padding:8px 12px;border-bottom:1px solid var(--border)">${val}</td>
        </tr>`).join("")}
    </table>`;
  document.getElementById("modal-overlay").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
}

/* ── Escape HTML ── */
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ── Auto-scroll log boxes ── */
setInterval(() => {
  document.querySelectorAll(".log-box").forEach(el => {
    el.scrollTop = el.scrollHeight;
  });
}, 500);
