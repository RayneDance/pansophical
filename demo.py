#!/usr/bin/env python3
"""
Pansophical Demo — Gemini + MCP Tool-Calling Harness

A minimal CLI that connects an LLM (Google Gemini) to Pansophical's
MCP server, demonstrating the full authorization and tool-calling pipeline.

Usage:
    python demo.py [--config config.toml] [--binary target/debug/pansophical.exe]

No pip dependencies — uses only Python stdlib.
"""

import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
import argparse
import textwrap

# ── Constants ──────────────────────────────────────────────────────────────

GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}"

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
        )

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
            raise RuntimeError("MCP server closed stdout unexpectedly")
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

    def initialize(self):
        """Perform the MCP initialize handshake."""
        resp = self.send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pansophical-demo", "version": "0.1.0"},
        })
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

# ── Gemini API ─────────────────────────────────────────────────────────────

def mcp_tools_to_gemini(mcp_tools):
    """Convert MCP tool definitions to Gemini function declarations."""
    declarations = []
    for tool in mcp_tools:
        schema = tool.get("inputSchema", {})
        # Gemini expects "parameters" with type "object".
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


def call_gemini(api_key, messages, tools_decl):
    """Call the Gemini API with messages and tool declarations."""
    url = GEMINI_URL.format(GEMINI_MODEL, api_key)

    body = {
        "contents": messages,
        "systemInstruction": {
            "parts": [{"text": SYSTEM_PROMPT}]
        },
    }

    if tools_decl:
        body["tools"] = [{"functionDeclarations": tools_decl}]

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        raise RuntimeError(f"Gemini API error ({e.code}): {error_body}")


def extract_response(gemini_resp):
    """Extract text and/or function calls from a Gemini response."""
    candidates = gemini_resp.get("candidates", [])
    if not candidates:
        return None, []

    parts = candidates[0].get("content", {}).get("parts", [])
    text_parts = []
    func_calls = []

    for part in parts:
        if "text" in part:
            text_parts.append(part["text"])
        if "functionCall" in part:
            func_calls.append(part["functionCall"])

    return "\n".join(text_parts) if text_parts else None, func_calls

# ── Main Loop ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Pansophical Demo — Gemini + MCP")
    parser.add_argument("--config", default="config.toml", help="Path to config.toml")
    parser.add_argument("--binary", default=None, help="Path to pansophical binary")
    args = parser.parse_args()

    # Find the binary.
    if args.binary:
        binary = args.binary
    elif os.path.exists("target/release/pansophical.exe"):
        binary = "target/release/pansophical.exe"
    elif os.path.exists("target/debug/pansophical.exe"):
        binary = "target/debug/pansophical.exe"
    elif os.path.exists("target/release/pansophical"):
        binary = "target/release/pansophical"
    elif os.path.exists("target/debug/pansophical"):
        binary = "target/debug/pansophical"
    else:
        cprint(C.RED, "Error: Could not find pansophical binary. Build first: cargo build")
        sys.exit(1)

    # Banner.
    print()
    cprint(C.BOLD + C.CYAN, "  ╔══════════════════════════════════════════╗")
    cprint(C.BOLD + C.CYAN, "  ║       Pansophical Demo Harness          ║")
    cprint(C.BOLD + C.CYAN, "  ║   Gemini + MCP Tool-Calling Pipeline    ║")
    cprint(C.BOLD + C.CYAN, "  ╚══════════════════════════════════════════╝")
    print()

    # Get API key.
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        cprint(C.YELLOW, "  Enter your Gemini API key (or set GEMINI_API_KEY env var):")
        api_key = input(f"  {C.DIM}>{C.RESET} ").strip()
        if not api_key:
            cprint(C.RED, "  No API key provided. Exiting.")
            sys.exit(1)
    print()

    # Start MCP server.
    cprint(C.DIM, f"  Starting MCP server: {binary} --config {args.config}")
    try:
        mcp = McpClient(binary, args.config)
    except Exception as e:
        cprint(C.RED, f"  Failed to start server: {e}")
        sys.exit(1)

    # Initialize.
    try:
        info = mcp.initialize()
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

    gemini_tools = mcp_tools_to_gemini(tools)
    print()
    cprint(C.DIM, "  Type your message, or 'quit' to exit.")
    cprint(C.DIM, "  ─────────────────────────────────────")
    print()

    # Conversation history (Gemini format).
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

            # Call Gemini (potentially multiple rounds for tool calls).
            max_rounds = 5
            for round_num in range(max_rounds):
                try:
                    gemini_resp = call_gemini(api_key, messages, gemini_tools)
                except Exception as e:
                    cprint(C.RED, f"\n  Gemini error: {e}")
                    break

                text, func_calls = extract_response(gemini_resp)

                if not func_calls:
                    # No tool calls — show the text response.
                    if text:
                        # Add to history.
                        messages.append({
                            "role": "model",
                            "parts": [{"text": text}],
                        })
                        print()
                        cprint(C.BOLD + C.GREEN, "  Gemini ▸ ", end="")
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
                model_parts = []
                func_response_parts = []

                for fc in func_calls:
                    tool_name = fc["name"]
                    tool_args = fc.get("args", {})

                    cprint(C.MAGENTA, f"\n  ⚙ Calling tool: {C.BOLD}{tool_name}{C.RESET}{C.MAGENTA} {json.dumps(tool_args)}")

                    model_parts.append({"functionCall": fc})

                    # Call via MCP.
                    result = mcp.call_tool(tool_name, tool_args)

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

                # Add the model's function call to history.
                messages.append({
                    "role": "model",
                    "parts": model_parts,
                })

                # Add the function results.
                messages.append({
                    "role": "user",
                    "parts": func_response_parts,
                })

                # Continue the loop — Gemini will process tool results.

    finally:
        cprint(C.DIM, "\n  Shutting down MCP server...")
        mcp.close()
        cprint(C.DIM, "  Goodbye.\n")


if __name__ == "__main__":
    main()
