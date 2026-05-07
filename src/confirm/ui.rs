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
