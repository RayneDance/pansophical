#!/usr/bin/env python3
"""
Pansophical Demo — Vertex AI + MCP Tool-Calling Harness

A minimal CLI that connects an LLM (Vertex AI) to Pansophical's
MCP server, demonstrating the full authorization and tool-calling pipeline.

Usage:
    python demo.py [--config config.toml] [--binary target/debug/pansophical.exe] [--debug]

No pip dependencies — uses only Python stdlib.
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import argparse
import re
import textwrap

# ── Constants ──────────────────────────────────────────────────────────────

VERTEX_MODEL = "gemini-2.5-flash"
VERTEX_URL = "https://us-central1-aiplatform.googleapis.com/v1/projects/{}/locations/us-central1/publishers/google/models/{}:generateContent"

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an AI assistant with access to tools provided by a secure MCP server.
    Use the available tools to help the user with their requests.
    When you use a tool, explain what you're doing and show the results.
    Be concise and helpful.
""")

# ── Colors ─────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    GREEN  = "\033[32m"
    BLUE   = "\033[34m"
    CYAN   = "\033[36m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    MAGENTA = "\033[35m"

def cprint(color, text, end="\n"):
    print(f"{color}{text}{C.RESET}", end=end)

class Spinner:
    """Animated spinner shown while waiting for the API."""
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label="Thinking"):
        self.label = label
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            print(f"\r  {C.DIM}{frame} {self.label}...{C.RESET}", end="", flush=True)
            i += 1
            self._stop.wait(0.1)
        # Clear the spinner line.
        print(f"\r{' ' * (len(self.label) + 12)}\r", end="", flush=True)

    def __enter__(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()

# ── MCP Client ─────────────────────────────────────────────────────────────

class McpClient:
    """Minimal MCP client over stdio."""

    def __init__(self, binary, config):
        self.req_id = 0
        args = [binary, "--config", config]
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
        # Drain stderr in a background thread to prevent pipe deadlock.
        # Without this, the server's tracing logs fill the stderr pipe buffer
        # (~4-64KB), the server blocks on its next stderr write, and we block
        # forever waiting for a stdout response.
        self._stderr_lines = []
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()

        # Give the server a moment to start up.
        import time
        time.sleep(0.5)
        # Check it didn't immediately crash.
        ret = self.proc.poll()
        if ret is not None:
            stderr = "\n".join(self._stderr_lines)
            raise RuntimeError(
                f"Server exited immediately (code {ret}).\nStderr:\n{stderr}"
            )

    def _drain_stderr(self):
        """Continuously read stderr so the pipe buffer never fills."""
        try:
            for line in self.proc.stderr:
                self._stderr_lines.append(line.rstrip())
                # Keep only last 200 lines to bound memory.
                if len(self._stderr_lines) > 200:
                    self._stderr_lines = self._stderr_lines[-100:]
        except (ValueError, OSError):
            pass  # Pipe closed.

    def _next_id(self):
        self.req_id += 1
        return self.req_id

    def send(self, method, params=None):
        """Send a JSON-RPC request and return the response."""
        msg = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            msg["params"] = params

        line = json.dumps(msg)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

        # Read the response line.
        resp_line = self.proc.stdout.readline()
        if not resp_line:
            # Server died — show captured stderr.
            stderr = "\n".join(self._stderr_lines[-50:])
            raise RuntimeError(
                f"MCP server closed stdout unexpectedly.\nStderr:\n{stderr}"
            )
        return json.loads(resp_line)

    def notify(self, method, params=None):
        """Send a JSON-RPC notification (no response expected)."""
        msg = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def initialize(self, mcp_token=None):
        """Perform the MCP initialize handshake."""
        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pansophical-demo", "version": "0.1.0"},
        }
        if mcp_token:
            params["_meta"] = {"token": mcp_token}

        resp = self.send("initialize", params)
        if "error" in resp:
            raise RuntimeError(f"Initialize failed: {resp['error']}")

        # Send initialized notification.
        self.notify("notifications/initialized")
        return resp.get("result", {})

    def list_tools(self):
        """Get the list of available tools."""
        resp = self.send("tools/list")
        if "error" in resp:
            raise RuntimeError(f"tools/list failed: {resp['error']}")
        return resp.get("result", {}).get("tools", [])

    def call_tool(self, name, arguments):
        """Call a tool and return the result."""
        resp = self.send("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            return {"error": resp["error"].get("message", str(resp["error"]))}
        return resp.get("result", {})

    def close(self):
        """Shut down the MCP server."""
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()

# ── Vertex AI ──────────────────────────────────────────────────────────────

def mcp_tools_to_vertex(mcp_tools):
    """Convert MCP tool definitions to Vertex function declarations."""
    declarations = []
    for tool in mcp_tools:
        schema = tool.get("inputSchema", {})
        # Vertex expects "parameters" with type "object".
        params = {
            "type": "object",
            "properties": schema.get("properties", {}),
        }
        required = schema.get("required", [])
        if required:
            params["required"] = required

        declarations.append({
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": params,
        })
    return declarations


def get_gcloud_auth():
    """Get project and access token from gcloud CLI."""
    gcloud_bin = "gcloud.cmd" if sys.platform == "win32" else "gcloud"
    try:
        token = subprocess.check_output([gcloud_bin, "auth", "print-access-token"], text=True, stderr=subprocess.DEVNULL).strip()
        project = subprocess.check_output([gcloud_bin, "config", "get-value", "project"], text=True, stderr=subprocess.DEVNULL).strip()
        if not project:
            raise RuntimeError("No gcloud project set. Run: gcloud config set project YOUR_PROJECT")
        return project, token
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to get gcloud auth. Are you logged in? Run: gcloud auth login")
    except FileNotFoundError:
        raise RuntimeError(f"Could not find {gcloud_bin} in PATH. Is Google Cloud SDK installed?")

def call_vertex(project, access_token, messages, tools_decl):
    """Call the Vertex AI API with messages and tool declarations."""
    url = VERTEX_URL.format(project, VERTEX_MODEL)

    body = {
        "contents": messages,
        "systemInstruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
    }

    if tools_decl:
        body["tools"] = [{"functionDeclarations": tools_decl}]

    # Enable thinking so the API returns thoughtSignature fields needed
    # for tool-call round-tripping.  Works with both 2.5 and 3.x models.
    body["generationConfig"] = {
        "thinkingConfig": {
            "includeThoughts": True,
        }
    }

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise RuntimeError(f"Vertex API error ({e.code}): {error_body}")


def extract_response(vertex_resp):
    """Extract text, function calls, thoughts, and raw parts from a Vertex response.

    Returns (text, func_calls, thoughts, raw_parts) where raw_parts preserves any
    opaque fields like ``thoughtSignature`` needed for round-tripping.
    """
    candidates = vertex_resp.get("candidates", [])
    if not candidates:
        return None, [], [], []

    parts = candidates[0].get("content", {}).get("parts", [])
    text_parts = []
    thought_parts = []
    func_calls = []

    for part in parts:
        if "text" in part:
            if part.get("thought"):
                thought_parts.append(part["text"])
            else:
                text_parts.append(part["text"])
        if "functionCall" in part:
            func_calls.append(part["functionCall"])

    thoughts = "\n".join(thought_parts) if thought_parts else None
    return "\n".join(text_parts) if text_parts else None, func_calls, thoughts, parts

# ── Main Loop ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Pansophical Demo — Vertex AI + MCP")
    parser.add_argument("--config", default="config.toml", help="Path to config.toml")
    parser.add_argument("--binary", default=None, help="Path to pansophical binary")
    parser.add_argument("--debug", action="store_true", help="Show server stderr logs after each tool call")
    args = parser.parse_args()

    # Find the binary — check cwd first, then target/.
    search = [
        "pansophical.exe",
        "pansophical",
        "target/release/pansophical.exe",
        "target/debug/pansophical.exe",
        "target/release/pansophical",
        "target/debug/pansophical",
    ]
    if args.binary:
        binary = args.binary
    else:
        binary = next((p for p in search if os.path.exists(p)), None)
        if binary is None:
            cprint(C.RED, "Error: Could not find pansophical binary. Build first: cargo build")
            sys.exit(1)

    # Banner.
    print()
    cprint(C.BOLD + C.CYAN, "  ╔══════════════════════════════════════════╗")
    cprint(C.BOLD + C.CYAN, "  ║       Pansophical Demo Harness          ║")
    cprint(C.BOLD + C.CYAN, "  ║   Vertex AI + MCP Tool-Calling Pipeline  ║")
    cprint(C.BOLD + C.CYAN, "  ╚══════════════════════════════════════════╝")
    print()

    # Get Vertex Auth.
    cprint(C.DIM, "  Authenticating with gcloud...")
    try:
        project, access_token = get_gcloud_auth()
    except Exception as e:
        cprint(C.RED, f"  {e}")
        sys.exit(1)
    
    cprint(C.GREEN, f"  ✓ Authenticated as project: {project}")
    print()

    # Start MCP server.
    cprint(C.DIM, f"  Starting MCP server: {binary} --config {args.config}")
    try:
        mcp = McpClient(binary, args.config)
    except Exception as e:
        cprint(C.RED, f"  Failed to start server: {e}")
        sys.exit(1)

    # Read MCP token from config.toml.
    mcp_token = os.environ.get("PANSOPHICAL_TOKEN", "")
    if not mcp_token:
        try:
            with open(args.config, "r") as f:
                config_text = f.read()
            # Find any `token = "..."` line in a [keys.*] section.
            # Handles comments and blank lines between header and token.
            match = re.search(
                r'\[keys\.\w+\].*?\ntoken\s*=\s*"([^"]+)"',
                config_text,
                re.DOTALL,
            )
            if match:
                mcp_token = match.group(1)
        except Exception:
            pass

    if mcp_token:
        cprint(C.DIM, f"  Using token: {mcp_token[:16]}...")
    else:
        cprint(C.YELLOW, "  No key token found in config.")
        cprint(C.YELLOW, "  Paste a token from your config.toml [keys.*] section, or press Enter to try without:")
        mcp_token = input(f"  {C.DIM}token>{C.RESET} ").strip() or None

    # Initialize.
    try:
        info = mcp.initialize(mcp_token)
        server_name = info.get("serverInfo", {}).get("name", "unknown")
        server_ver = info.get("serverInfo", {}).get("version", "?")
        cprint(C.GREEN, f"  ✓ Connected to {server_name} v{server_ver}")
    except Exception as e:
        cprint(C.RED, f"  Initialize failed: {e}")
        mcp.close()
        sys.exit(1)

    # Get tools.
    try:
        tools = mcp.list_tools()
        cprint(C.GREEN, f"  ✓ {len(tools)} tools available: {', '.join(t['name'] for t in tools)}")
    except Exception as e:
        cprint(C.RED, f"  tools/list failed: {e}")
        mcp.close()
        sys.exit(1)

    vertex_tools = mcp_tools_to_vertex(tools)
    print()
    cprint(C.DIM, "  Type your message, or 'quit' to exit.")
    cprint(C.DIM, "  ─────────────────────────────────────")
    print()

    # Conversation history (Vertex format).
    messages = []

    try:
        while True:
            # User input.
            try:
                user_input = input(f"  {C.BOLD}{C.BLUE}You ▸{C.RESET} ")
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if user_input.strip().lower() in ("quit", "exit", "q"):
                break
            if not user_input.strip():
                continue

            # Add user message.
            messages.append({
                "role": "user",
                "parts": [{"text": user_input}],
            })

            # Call Vertex AI (potentially multiple rounds for tool calls).
            max_rounds = 5
            for round_num in range(max_rounds):
                try:
                    with Spinner("Waiting for Vertex AI"):
                        vertex_resp = call_vertex(project, access_token, messages, vertex_tools)
                except Exception as e:
                    cprint(C.RED, f"\n  Vertex error: {e}")
                    break

                text, func_calls, thoughts, raw_parts = extract_response(vertex_resp)

                # Show thinking output if present.
                if thoughts:
                    print()
                    cprint(C.DIM, "  🧠 Thinking:")
                    for line in thoughts.split("\n"):
                        # Truncate very long thought lines.
                        if len(line) > 120:
                            line = line[:117] + "..."
                        cprint(C.DIM, f"     {line}")

                if not func_calls:
                    # No tool calls — show the text response.
                    if text:
                        # Add to history — preserve raw parts so any
                        # thoughtSignature fields are round-tripped.
                        messages.append({
                            "role": "model",
                            "parts": raw_parts,
                        })
                        print()
                        cprint(C.BOLD + C.GREEN, "  Vertex ▸ ", end="")
                        # Word-wrap the response.
                        lines = text.split("\n")
                        for i, line in enumerate(lines):
                            if i == 0:
                                print(line)
                            else:
                                print(f"           {line}")
                        print()
                    else:
                        cprint(C.DIM, "\n  (empty response)\n")
                    break

                # Execute tool calls.
                func_response_parts = []

                for fc in func_calls:
                    tool_name = fc["name"]
                    tool_args = fc.get("args", {})

                    cprint(C.MAGENTA, f"\n  ⚙ Calling tool: {C.BOLD}{tool_name}{C.RESET}{C.MAGENTA} {json.dumps(tool_args)}")

                    # Capture stderr line count before the call.
                    stderr_before = len(mcp._stderr_lines)

                    # Call via MCP.
                    result = mcp.call_tool(tool_name, tool_args)

                    # Show server logs emitted during the tool call (debug mode only).
                    new_stderr = mcp._stderr_lines[stderr_before:]
                    if args.debug and new_stderr:
                        cprint(C.DIM, f"  📋 Server logs ({len(new_stderr)} lines):")
                        for log_line in new_stderr[-30:]:
                            # Truncate long lines.
                            display = log_line[:250] + "..." if len(log_line) > 250 else log_line
                            cprint(C.DIM, f"     {display}")

                    if "error" in result:
                        cprint(C.RED, f"  ✗ Error: {result['error']}")
                        result_text = f"Error: {result['error']}"
                    else:
                        # Extract text from content array.
                        content = result.get("content", [])
                        result_text = "\n".join(
                            c.get("text", "") for c in content if c.get("type") == "text"
                        )
                        # Show a preview.
                        preview = result_text[:200]
                        if len(result_text) > 200:
                            preview += "..."
                        cprint(C.CYAN, f"  ✓ Result: {preview}")

                    func_response_parts.append({
                        "functionResponse": {
                            "name": tool_name,
                            "response": {"result": result_text},
                        }
                    })

                # Add the model's function call to history — use raw_parts
                # from the API response so that thoughtSignature fields are
                # preserved exactly as received.  Gemini 3.x *requires* these
                # signatures to be round-tripped; 2.5 models benefit from it.
                messages.append({
                    "role": "model",
                    "parts": raw_parts,
                })

                # Add the function results.
                messages.append({
                    "role": "user",
                    "parts": func_response_parts,
                })

                # Continue the loop — Vertex will process tool results.

    finally:
        cprint(C.DIM, "\n  Shutting down MCP server...")
        mcp.close()
        cprint(C.DIM, "  Goodbye.\n")


if __name__ == "__main__":
    main()
