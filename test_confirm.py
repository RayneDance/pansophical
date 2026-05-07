#!/usr/bin/env python3
"""Minimal test harness for confirm flow — no LLM needed."""

import json
import subprocess
import sys
import threading
import time

BINARY = r"target\debug\pansophical.exe"
CONFIG = "config.toml"

class McpTest:
    def __init__(self):
        self.req_id = 0
        self.proc = subprocess.Popen(
            [BINARY, "--config", CONFIG],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stderr_lines = []
        self._t = threading.Thread(target=self._drain, daemon=True)
        self._t.start()
        time.sleep(0.5)
        if self.proc.poll() is not None:
            print("Server died:", "\n".join(self._stderr_lines))
            sys.exit(1)

    def _drain(self):
        try:
            for line in self.proc.stderr:
                self._stderr_lines.append(line.rstrip())
                # Print server logs in real time
                print(f"  [server] {line.rstrip()}")
                if len(self._stderr_lines) > 500:
                    self._stderr_lines = self._stderr_lines[-200:]
        except:
            pass

    def send(self, method, params=None):
        self.req_id += 1
        msg = {"jsonrpc": "2.0", "id": self.req_id, "method": method}
        if params:
            msg["params"] = params
        line = json.dumps(msg)
        print(f"  -> {method} (id={self.req_id})")
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        resp = self.proc.stdout.readline()
        if not resp:
            print("Server closed stdout. Stderr:", "\n".join(self._stderr_lines[-20:]))
            sys.exit(1)
        data = json.loads(resp)
        if "error" in data:
            print(f"  <- ERROR: {data['error']}")
        else:
            result = data.get("result", {})
            # Truncate for display
            text = json.dumps(result)
            if len(text) > 200:
                text = text[:200] + "..."
            print(f"  <- OK: {text}")
        return data

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

def main():
    print("Starting MCP server...")
    mcp = McpTest()

    # Initialize
    resp = mcp.send("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0.1"},
        "_meta": {"token": "test"},
    })
    mcp.notify("notifications/initialized")

    # List tools
    resp = mcp.send("tools/list")
    tools = resp.get("result", {}).get("tools", [])
    print(f"\n  Tools: {[t['name'] for t in tools]}\n")

    # Call a tool that should trigger confirm (or just execute)
    print("Calling builtin_list_dir on E:/pansophical ...")
    resp = mcp.send("tools/call", {
        "name": "builtin_list_dir",
        "arguments": {"path": "E:/pansophical"}
    })

    print("\nCall complete. Server still running — check browser for confirm page.")
    print("Press Enter to call another tool, or Ctrl+C to quit.\n")

    try:
        while True:
            cmd = input("tool> ").strip()
            if not cmd:
                continue
            if cmd == "quit":
                break
            # Parse: tool_name {"arg": "val"}
            parts = cmd.split(" ", 1)
            name = parts[0]
            args = json.loads(parts[1]) if len(parts) > 1 else {}
            mcp.send("tools/call", {"name": name, "arguments": args})
    except (KeyboardInterrupt, EOFError):
        pass

    print("\nShutting down...")
    mcp.proc.stdin.close()
    mcp.proc.wait(timeout=3)

if __name__ == "__main__":
    main()
