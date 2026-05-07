//! Embedded approval UI page.

/// Generate the HTML approval page for a pending confirmation.
pub fn approval_page(
    tool_name: &str,
    resource: &str,
    perm: &str,
    key_name: &str,
    token: &str,
    ttl_secs: u64,
) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pansophical — Confirm Action</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --border: #334155;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #eab308;
    --font: 'Inter', system-ui, -apple-system, sans-serif;
  }}
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2.5rem;
    max-width: 520px;
    width: 100%;
    box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
  }}
  .header {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }}
  .header .icon {{
    width: 40px; height: 40px;
    background: rgba(234, 179, 8, 0.15);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
  }}
  .header h1 {{
    font-size: 1.25rem;
    font-weight: 600;
  }}
  .details {{
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem;
    margin-bottom: 1.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    line-height: 1.8;
  }}
  .details .label {{
    color: var(--muted);
    font-family: var(--font);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .details .value {{
    color: var(--text);
    word-break: break-all;
  }}
  .timer {{
    text-align: center;
    color: var(--yellow);
    font-size: 0.85rem;
    margin-bottom: 1.25rem;
    font-weight: 500;
  }}
  .scope-row {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }}
  .scope-btn {{
    flex: 1;
    min-width: 100px;
    padding: 0.5rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.8rem;
    font-family: var(--font);
    transition: all 0.15s;
  }}
  .scope-btn.active {{
    border-color: var(--green);
    color: var(--text);
    background: rgba(34, 197, 94, 0.1);
  }}
  .scope-btn:hover {{
    border-color: var(--text);
    color: var(--text);
  }}
  .actions {{
    display: flex;
    gap: 0.75rem;
  }}
  .btn {{
    flex: 1;
    padding: 0.85rem;
    border: none;
    border-radius: 10px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    font-family: var(--font);
    transition: all 0.15s;
  }}
  .btn-approve {{
    background: var(--green);
    color: #000;
  }}
  .btn-approve:hover {{ background: #16a34a; }}
  .btn-deny {{
    background: transparent;
    color: var(--red);
    border: 1px solid var(--red);
  }}
  .btn-deny:hover {{ background: rgba(239,68,68,0.1); }}
  .btn:disabled {{
    opacity: 0.5;
    cursor: not-allowed;
  }}
  .result {{
    text-align: center;
    padding: 1rem;
    border-radius: 10px;
    font-weight: 600;
    display: none;
    margin-top: 1rem;
  }}
  .result.approved {{
    background: rgba(34, 197, 94, 0.15);
    color: var(--green);
    display: block;
  }}
  .result.denied {{
    background: rgba(239, 68, 68, 0.15);
    color: var(--red);
    display: block;
  }}
  .result.expired {{
    background: rgba(234, 179, 8, 0.15);
    color: var(--yellow);
    display: block;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="icon">⚠️</div>
    <h1>Confirmation Required</h1>
  </div>

  <div class="details">
    <div class="label">Tool</div>
    <div class="value">{tool_name}</div>
    <br>
    <div class="label">Resource</div>
    <div class="value">{resource}</div>
    <br>
    <div class="label">Permission</div>
    <div class="value">{perm}</div>
    <br>
    <div class="label">Key</div>
    <div class="value">{key_name}</div>
  </div>

  <div class="timer" id="timer">Expires in {ttl_secs}s</div>

  <div class="scope-row">
    <button class="scope-btn active" data-scope="once" onclick="setScope(this)">Once</button>
    <button class="scope-btn" data-scope="minutes:5" onclick="setScope(this)">5 Minutes</button>
    <button class="scope-btn" data-scope="minutes:30" onclick="setScope(this)">30 Minutes</button>
    <button class="scope-btn" data-scope="session" onclick="setScope(this)">Session</button>
  </div>

  <div class="actions" id="actions">
    <button class="btn btn-deny" onclick="decide('deny')">Deny</button>
    <button class="btn btn-approve" onclick="decide('approve')">Approve</button>
  </div>

  <div class="result" id="result"></div>
</div>

<script>
  const TOKEN = "{token}";
  const TTL = {ttl_secs};
  let scope = "once";
  let remaining = TTL;
  let decided = false;

  function setScope(el) {{
    document.querySelectorAll('.scope-btn').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    scope = el.dataset.scope;
  }}

  function decide(action) {{
    if (decided) return;
    decided = true;
    document.querySelectorAll('.btn').forEach(b => b.disabled = true);

    fetch(`/confirm/${{TOKEN}}/${{action}}`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ scope: scope }})
    }})
    .then(r => r.json())
    .then(data => {{
      const el = document.getElementById('result');
      if (data.ok) {{
        el.className = 'result ' + (action === 'approve' ? 'approved' : 'denied');
        el.textContent = action === 'approve' ? '✓ Approved' : '✕ Denied';
      }} else {{
        el.className = 'result denied';
        el.textContent = data.error || 'Failed';
      }}
    }})
    .catch(err => {{
      const el = document.getElementById('result');
      el.className = 'result denied';
      el.textContent = 'Network error: ' + err.message;
    }});
  }}

  setInterval(() => {{
    if (decided) return;
    remaining--;
    const el = document.getElementById('timer');
    if (remaining <= 0) {{
      el.textContent = 'Expired';
      decided = true;
      document.querySelectorAll('.btn').forEach(b => b.disabled = true);
      const r = document.getElementById('result');
      r.className = 'result expired';
      r.textContent = '⏱ Token expired — request auto-denied';
    }} else {{
      el.textContent = `Expires in ${{remaining}}s`;
    }}
  }}, 1000);
</script>
</body>
</html>"##,
        tool_name = tool_name,
        resource = resource,
        perm = perm,
        key_name = key_name,
        token = token,
        ttl_secs = ttl_secs,
    )
}

/// Generate the admin dashboard SPA page.
pub fn dashboard_page(
    version: &str,
    tools_json: &str,
    keys_json: &str,
    pending_count: usize,
    uptime: &str,
) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pansophical — Admin Dashboard</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface-hover: #263548;
    --border: #334155;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #eab308;
    --blue: #3b82f6;
    --purple: #a855f7;
    --cyan: #06b6d4;
    --font: 'Inter', system-ui, -apple-system, sans-serif;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
  }}
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }}
  .topbar {{
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0.75rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(12px);
  }}
  .topbar .brand {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }}
  .topbar .brand .logo {{
    width: 32px; height: 32px;
    background: linear-gradient(135deg, var(--blue), var(--purple));
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    font-weight: 700;
  }}
  .topbar .brand h1 {{
    font-size: 1.1rem;
    font-weight: 600;
  }}
  .topbar .brand .version {{
    font-size: 0.7rem;
    color: var(--muted);
    background: rgba(255,255,255,0.08);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
  }}
  .topbar .status {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8rem;
    color: var(--green);
  }}
  .topbar .status .dot {{
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.4; }}
  }}
  .nav {{
    display: flex;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    gap: 0;
  }}
  .nav button {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.75rem 1.25rem;
    cursor: pointer;
    font-family: var(--font);
    font-size: 0.85rem;
    font-weight: 500;
    transition: all 0.15s;
  }}
  .nav button:hover {{ color: var(--text); }}
  .nav button.active {{
    color: var(--text);
    border-bottom-color: var(--blue);
  }}
  .content {{
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    transition: transform 0.15s, border-color 0.15s;
  }}
  .stat-card:hover {{
    transform: translateY(-2px);
    border-color: var(--blue);
  }}
  .stat-card .label {{
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
  }}
  .stat-card .value {{
    font-size: 1.75rem;
    font-weight: 700;
  }}
  .stat-card .value.green {{ color: var(--green); }}
  .stat-card .value.yellow {{ color: var(--yellow); }}
  .stat-card .value.blue {{ color: var(--blue); }}
  .stat-card .value.purple {{ color: var(--purple); }}
  .table-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 2rem;
  }}
  .table-card h2 {{
    font-size: 1rem;
    font-weight: 600;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
  }}
  th {{
    text-align: left;
    padding: 0.75rem 1.25rem;
    font-size: 0.7rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.75rem 1.25rem;
    font-size: 0.85rem;
    border-bottom: 1px solid rgba(51,65,85,0.5);
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--surface-hover); }}
  .tag {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    font-family: var(--mono);
  }}
  .tag-grant {{ background: rgba(34,197,94,0.15); color: var(--green); }}
  .tag-deny {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .tag-tool {{ background: rgba(59,130,246,0.15); color: var(--blue); }}
  .tag-builtin {{ background: rgba(168,85,247,0.15); color: var(--purple); }}
  .tag-script {{ background: rgba(6,182,212,0.15); color: var(--cyan); }}
  .audit-log {{
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    line-height: 1.6;
    max-height: 500px;
    overflow-y: auto;
    color: var(--muted);
  }}
  .audit-log .entry {{ margin-bottom: 0.25rem; }}
  .audit-log .ts {{ color: var(--muted); }}
  .audit-log .granted {{ color: var(--green); }}
  .audit-log .denied {{ color: var(--red); }}
  .audit-log .pending {{ color: var(--yellow); }}
  .page {{ display: none; }}
  .page.active {{ display: block; }}
  .empty {{
    text-align: center;
    padding: 3rem;
    color: var(--muted);
    font-size: 0.9rem;
  }}
  .refresh-btn {{
    background: var(--blue);
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-family: var(--font);
    font-weight: 500;
    font-size: 0.8rem;
    transition: opacity 0.15s;
  }}
  .refresh-btn:hover {{ opacity: 0.85; }}
  .badge {{
    background: var(--yellow);
    color: #000;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.1rem 0.45rem;
    border-radius: 10px;
    margin-left: 0.35rem;
    vertical-align: middle;
  }}
  .badge.zero {{ background: var(--border); color: var(--muted); }}
  .request-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    margin-bottom: 1rem;
    transition: border-color 0.15s;
  }}
  .request-card:hover {{ border-color: var(--yellow); }}
  .request-card .req-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }}
  .request-card .req-tool {{
    font-weight: 600;
    font-size: 1rem;
  }}
  .request-card .req-timer {{
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--yellow);
  }}
  .request-card .req-details {{
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--muted);
    background: rgba(0,0,0,0.25);
    padding: 0.75rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    line-height: 1.7;
  }}
  .request-card .req-actions {{
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-wrap: wrap;
  }}
  .request-card .req-actions select {{
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    font-family: var(--font);
    font-size: 0.8rem;
  }}
  .request-card .req-actions button {{
    padding: 0.4rem 1rem;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    cursor: pointer;
    transition: opacity 0.15s;
  }}
  .request-card .req-actions button:hover {{ opacity: 0.85; }}
  .request-card .req-actions button:disabled {{ opacity: 0.4; cursor: default; }}
  .req-approve {{ background: var(--green); color: #000; }}
  .req-deny {{ background: var(--red); color: #fff; }}
  .req-result {{
    font-size: 0.85rem;
    font-weight: 600;
    margin-left: 0.5rem;
  }}
  .req-result.approved {{ color: var(--green); }}
  .req-result.denied {{ color: var(--red); }}
  .requests-empty {{
    text-align: center;
    padding: 3rem;
    color: var(--muted);
    font-size: 0.9rem;
  }}
  .requests-empty .icon {{ font-size: 2.5rem; margin-bottom: 0.75rem; }}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <div class="logo">P</div>
    <h1>Pansophical</h1>
    <span class="version">v{version}</span>
  </div>
  <div class="status">
    <div class="dot"></div>
    Running · {uptime}
  </div>
</div>

<div class="nav">
  <button class="active" onclick="showPage('dashboard', this)">📊 Dashboard</button>
  <button onclick="showPage('requests', this)" id="nav-requests">📨 Requests <span class="badge zero" id="req-badge">0</span></button>
  <button onclick="showPage('tools', this)">🔧 Tools</button>
  <button onclick="showPage('keys', this)">🔑 Keys</button>
  <button onclick="showPage('audit', this)">📋 Audit</button>
</div>

<div class="content">
  <!-- Dashboard -->
  <div class="page active" id="page-dashboard">
    <div class="grid">
      <div class="stat-card">
        <div class="label">Status</div>
        <div class="value green">Online</div>
      </div>
      <div class="stat-card">
        <div class="label">Pending Confirms</div>
        <div class="value yellow">{pending_count}</div>
      </div>
      <div class="stat-card">
        <div class="label">Registered Tools</div>
        <div class="value blue" id="tool-count">—</div>
      </div>
      <div class="stat-card">
        <div class="label">Active Keys</div>
        <div class="value purple" id="key-count">—</div>
      </div>
    </div>
  </div>

  <!-- Requests -->
  <div class="page" id="page-requests">
    <div id="requests-container">
      <div class="requests-empty">
        <div class="icon">✅</div>
        No pending requests
      </div>
    </div>
  </div>

  <!-- Tools -->
  <div class="page" id="page-tools">
    <div class="table-card">
      <h2>🔧 Registered Tools</h2>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead>
        <tbody id="tools-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Keys -->
  <div class="page" id="page-keys">
    <div class="table-card">
      <h2>🔑 Configured Keys</h2>
      <table>
        <thead><tr><th>Name</th><th>Rules</th></tr></thead>
        <tbody id="keys-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Audit -->
  <div class="page" id="page-audit">
    <div class="table-card">
      <h2>📋 Audit Log <button class="refresh-btn" style="margin-left: auto" onclick="loadAudit()">Refresh</button></h2>
      <div class="audit-log" id="audit-log">
        <div class="empty">Loading audit log...</div>
      </div>
    </div>
  </div>
</div>

<script>
  const TOOLS = {tools_json};
  const KEYS = {keys_json};

  // Populate tool count
  document.getElementById('tool-count').textContent = TOOLS.length;
  document.getElementById('key-count').textContent = Object.keys(KEYS).length;

  // Populate tools table
  const toolsBody = document.getElementById('tools-body');
  if (TOOLS.length === 0) {{
    toolsBody.innerHTML = '<tr><td colspan="3" class="empty">No tools registered</td></tr>';
  }} else {{
    TOOLS.forEach(t => {{
      const prefix = t.name.split('_')[0];
      const tagClass = prefix === 'builtin' ? 'tag-builtin' : 'tag-script';
      const tagLabel = prefix === 'builtin' ? 'builtin' : prefix;
      toolsBody.innerHTML += `<tr><td><span class="tag tag-tool">${{t.name}}</span></td><td><span class="tag ${{tagClass}}">${{tagLabel}}</span></td><td>${{t.description}}</td></tr>`;
    }});
  }}

  // Populate keys table
  const keysBody = document.getElementById('keys-body');
  const keyEntries = Object.entries(KEYS);
  if (keyEntries.length === 0) {{
    keysBody.innerHTML = '<tr><td colspan="2" class="empty">No keys configured</td></tr>';
  }} else {{
    keyEntries.forEach(([name, rules]) => {{
      const rulesHtml = (Array.isArray(rules) ? rules : []).map(r => {{
        const tag = r.effect === 'grant' ? 'tag-grant' : 'tag-deny';
        const detail = r.type === 'tool' ? r.name : (r.path || '') + ' ' + (r.perm || '');
        return `<span class="tag ${{tag}}">${{r.effect}}</span> ${{r.type}}: ${{detail}}`;
      }}).join('<br>');
      keysBody.innerHTML += `<tr><td><strong>${{name}}</strong></td><td>${{rulesHtml || '<em>No rules</em>'}}</td></tr>`;
    }});
  }}

  function showPage(name, btn) {{
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    btn.classList.add('active');
    if (name === 'audit') loadAudit();
    if (name === 'requests') loadPending();
  }}

  // ── Pending Requests ──────────────────────────────────────────────────
  let pendingData = [];
  const decidedTokens = new Set();

  function loadPending() {{
    fetch('/api/pending')
      .then(r => r.json())
      .then(items => {{
        pendingData = items || [];
        const badge = document.getElementById('req-badge');
        badge.textContent = pendingData.length;
        badge.className = 'badge' + (pendingData.length === 0 ? ' zero' : '');

        const container = document.getElementById('requests-container');
        if (pendingData.length === 0) {{
          container.innerHTML = '<div class="requests-empty"><div class="icon">✅</div>No pending requests</div>';
          return;
        }}
        container.innerHTML = pendingData.map(r => {{
          const decided = decidedTokens.has(r.token);
          return `<div class="request-card" id="req-${{r.token}}">
            <div class="req-header">
              <div class="req-tool">📨 ${{r.tool_name}}</div>
              <div class="req-timer" id="timer-${{r.token}}">${{r.remaining_secs}}s</div>
            </div>
            <div class="req-details">
              <strong>Resource:</strong> ${{r.resource}}<br>
              <strong>Permission:</strong> ${{r.perm}}<br>
              <strong>Key:</strong> ${{r.key_name}}
            </div>
            <div class="req-actions">
              <select id="scope-${{r.token}}" ${{decided ? 'disabled' : ''}}>
                <option value="once">Once</option>
                <option value="minutes:5">5 Minutes</option>
                <option value="minutes:30">30 Minutes</option>
                <option value="session">Session</option>
              </select>
              <button class="req-approve" onclick="decideReq('${{r.token}}','approve')" ${{decided ? 'disabled' : ''}}>✓ Approve</button>
              <button class="req-deny" onclick="decideReq('${{r.token}}','deny')" ${{decided ? 'disabled' : ''}}>✕ Deny</button>
              <span class="req-result" id="result-${{r.token}}"></span>
            </div>
          </div>`;
        }}).join('');
      }})
      .catch(() => {{}});
  }}

  function decideReq(token, action) {{
    const scope = document.getElementById('scope-' + token)?.value || 'once';
    decidedTokens.add(token);
    // Disable buttons immediately.
    const card = document.getElementById('req-' + token);
    if (card) {{
      card.querySelectorAll('button, select').forEach(el => el.disabled = true);
    }}
    fetch(`/confirm/${{token}}/${{action}}`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ scope: scope }})
    }})
    .then(r => r.json())
    .then(data => {{
      const el = document.getElementById('result-' + token);
      if (data.ok) {{
        el.className = 'req-result ' + (action === 'approve' ? 'approved' : 'denied');
        el.textContent = action === 'approve' ? '✓ Approved' : '✕ Denied';
        // Remove card after animation.
        setTimeout(() => loadPending(), 1500);
      }} else {{
        el.className = 'req-result denied';
        el.textContent = data.error || 'Error';
      }}
    }})
    .catch(err => {{
      const el = document.getElementById('result-' + token);
      if (el) {{ el.textContent = 'Network error'; el.className = 'req-result denied'; }}
    }});
  }}

  // Poll for pending requests every 2 seconds.
  setInterval(loadPending, 2000);
  loadPending();

  // ── Audit Log ─────────────────────────────────────────────────────────

  function loadAudit() {{
    fetch('/api/audit')
      .then(r => r.json())
      .then(entries => {{
        const el = document.getElementById('audit-log');
        if (!entries || entries.length === 0) {{
          el.innerHTML = '<div class="empty">No audit entries</div>';
          return;
        }}
        el.innerHTML = entries.map(e => {{
          const cls = e.decision === 'granted' ? 'granted' : e.decision === 'denied' ? 'denied' : 'pending';
          const time = e.ts ? e.ts.replace('T', ' ').substring(0, 19) : '-';
          const who = e.key || '-';
          const tool = e.tool ? `<strong>${{e.tool}}</strong> ` : '';
          const detail = e.detail || e.event || '';
          const outcome = e.outcome ? ` → ${{e.outcome}}` : '';
          return `<div class="entry"><span class="ts">${{time}}</span> <span class="${{cls}}">${{who}}</span> [<span class="${{cls}}">${{e.decision || '-'}}</span>] ${{tool}}${{detail}}${{outcome}}</div>`;
        }}).join('');
      }})
      .catch(err => {{
        document.getElementById('audit-log').innerHTML = '<div class="empty">Failed to load: ' + err.message + '</div>';
      }});
  }}
</script>
</body>
</html>"##,
        version = version,
        tools_json = tools_json,
        keys_json = keys_json,
        pending_count = pending_count,
        uptime = uptime,
    )
}

