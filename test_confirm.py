#!/usr/bin/env python3
"""Minimal test: request_access then list_dir."""

import json, subprocess, sys, threading, time, os

BINARY = r"target\debug\pansophical.exe"
CONFIG = "config.toml"

class Mcp:
    def __init__(self):
        self.rid = 0
        env = os.environ.copy()
        env["RUST_LOG"] = "debug"
        self.proc = subprocess.Popen(
            [BINARY, "--config", CONFIG],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env,
        )
        self._lines = []
        self._t = threading.Thread(target=self._drain, daemon=True)
        self._t.start()
        time.sleep(0.5)

    def _drain(self):
        for line in self.proc.stderr:
            l = line.rstrip()
            self._lines.append(l)
            # Only print lines with our debug markers
            if any(k in l for k in ["ephemeral", "Ephemeral", "Storing", "grant"]):
                print(f"  [DBG] {l}")
            elif "ERROR" in l or "WARN" in l:
                print(f"  [LOG] {l}")

    def send(self, method, params=None):
        self.rid += 1
        msg = {"jsonrpc": "2.0", "id": self.rid, "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        resp = self.proc.stdout.readline()
        if not resp:
            print("Server closed. Last stderr:")
            for l in self._lines[-10:]: print(f"  {l}")
            sys.exit(1)
        data = json.loads(resp)
        if "error" in data:
            print(f"  <- ERROR: {data['error']['message']}")
        else:
            r = data.get("result", {})
            t = json.dumps(r)
            print(f"  <- OK: {t[:120]}...")
        return data

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params: msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

def main():
    print("Starting server...")
    mcp = Mcp()

    mcp.send("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0.1"},
        "_meta": {"token": "test"},
    })
    mcp.notify("notifications/initialized")

    print("\n--- Step 1: list_dir E:\\ (should be denied) ---")
    mcp.send("tools/call", {"name": "builtin_list_dir", "arguments": {"path": "E:\\"}})

    print("\n--- Step 2: request_access for E:\\ ---")
    print("  (Approve this in the browser!)")
    mcp.send("tools/call", {"name": "builtin_request_access", "arguments": {
        "resource_type": "filesystem",
        "resource": "E:\\",
        "permission": "r",
        "reason": "test"
    }})

    # Give the cache a moment
    time.sleep(0.5)

    print("\n--- Step 3: list_dir E:\\ again (should work now) ---")
    mcp.send("tools/call", {"name": "builtin_list_dir", "arguments": {"path": "E:\\"}})

    print("\nDone. Dumping ephemeral-related logs:")
    for l in self._lines:
        if any(k in l for k in ["ephemeral", "Ephemeral", "Storing", "grant", "cache"]):
            print(f"  {l}")

    mcp.proc.stdin.close()
    try: mcp.proc.wait(timeout=3)
    except: mcp.proc.kill()

if __name__ == "__main__":
    main()
