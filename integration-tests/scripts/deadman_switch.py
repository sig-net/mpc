#!/usr/bin/env python3
"""
DeadmanSwitch - A watchdog process that kills orphaned test processes.

This script runs as an HTTP server that:
1. Accepts /watch requests to register PIDs to monitor
2. Accepts /ping requests to reset the deadman timer
3. Kills all watched processes if no ping is received within TIMEOUT_SECONDS

Usage:
    python3 deadman_switch.py [--port PORT]

Environment:
    MPC_KEEP_ENV=1  - If set, the switch will not kill processes (useful for debugging)
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json

# Configuration
DEFAULT_PORT = 19850
PING_TIMEOUT_SECONDS = 90
CHECK_INTERVAL_SECONDS = 5

# Global state
watched_pids: set[int] = set()
watched_containers: set[str] = set()
last_ping_time: float = time.time()
lock = threading.Lock()
shutdown_event = threading.Event()


def log(msg: str):
    """Log with timestamp."""
    print(f"[deadman_switch] {time.strftime('%H:%M:%S')} {msg}", flush=True)


def kill_process(pid: int) -> bool:
    """Attempt to kill a process by PID. Returns True if successful."""
    try:
        os.kill(pid, signal.SIGTERM)
        log(f"sent SIGTERM to PID {pid}")
        # Give it a moment to terminate gracefully
        time.sleep(0.5)
        try:
            os.kill(pid, 0)  # Check if still alive
            os.kill(pid, signal.SIGKILL)
            log(f"sent SIGKILL to PID {pid}")
        except OSError:
            pass  # Process already dead
        return True
    except OSError as e:
        log(f"failed to kill PID {pid}: {e}")
        return False


def kill_container(container_id: str) -> bool:
    """Attempt to kill a Docker container. Returns True if successful."""
    try:
        result = subprocess.run(
            ["docker", "kill", container_id],
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            log(f"killed container {container_id}")
            return True
        else:
            log(f"failed to kill container {container_id}: {result.stderr.decode()}")
            return False
    except Exception as e:
        log(f"error killing container {container_id}: {e}")
        return False


def cleanup_all():
    """Kill all watched processes and containers."""
    log("TIMEOUT - no ping received, cleaning up all watched processes...")
    
    with lock:
        pids = list(watched_pids)
        containers = list(watched_containers)
    
    for pid in pids:
        kill_process(pid)
    
    for container_id in containers:
        kill_container(container_id)
    
    log(f"cleanup complete: {len(pids)} processes, {len(containers)} containers")


def watchdog_thread():
    """Background thread that checks for ping timeout."""
    while not shutdown_event.is_set():
        time.sleep(CHECK_INTERVAL_SECONDS)
        
        with lock:
            elapsed = time.time() - last_ping_time
            has_watched = len(watched_pids) > 0 or len(watched_containers) > 0
        
        if has_watched and elapsed > PING_TIMEOUT_SECONDS:
            log(f"no ping for {elapsed:.1f}s (timeout={PING_TIMEOUT_SECONDS}s)")
            cleanup_all()
            # After cleanup, reset so we don't keep killing
            with lock:
                watched_pids.clear()
                watched_containers.clear()


class DeadmanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the deadman switch."""
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def send_json(self, status: int, data: dict):
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        
        if parsed.path == "/ping":
            global last_ping_time
            with lock:
                last_ping_time = time.time()
                status = {
                    "status": "ok",
                    "watched_pids": list(watched_pids),
                    "watched_containers": list(watched_containers),
                    "last_ping": last_ping_time,
                }
            log(f"ping received, watching {len(watched_pids)} PIDs, {len(watched_containers)} containers")
            self.send_json(200, status)
        
        elif parsed.path == "/status":
            with lock:
                elapsed = time.time() - last_ping_time
                status = {
                    "status": "ok",
                    "watched_pids": list(watched_pids),
                    "watched_containers": list(watched_containers),
                    "seconds_since_ping": elapsed,
                    "timeout_seconds": PING_TIMEOUT_SECONDS,
                }
            self.send_json(200, status)
        
        elif parsed.path == "/shutdown":
            log("shutdown requested")
            self.send_json(200, {"status": "shutting down"})
            shutdown_event.set()
        
        else:
            self.send_json(404, {"error": "not found"})
    
    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        
        if parsed.path == "/watch":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json(400, {"error": "invalid JSON"})
                return
            
            pids = data.get("pids", [])
            containers = data.get("containers", [])
            
            with lock:
                for pid in pids:
                    if isinstance(pid, int) and pid > 0:
                        watched_pids.add(pid)
                        log(f"watching PID {pid}")
                
                for container_id in containers:
                    if isinstance(container_id, str) and container_id:
                        watched_containers.add(container_id)
                        log(f"watching container {container_id}")
                
                result = {
                    "status": "ok",
                    "watched_pids": list(watched_pids),
                    "watched_containers": list(watched_containers),
                }
            
            self.send_json(200, result)
        
        elif parsed.path == "/unwatch":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self.send_json(400, {"error": "invalid JSON"})
                return
            
            pids = data.get("pids", [])
            containers = data.get("containers", [])
            
            with lock:
                for pid in pids:
                    watched_pids.discard(pid)
                    log(f"unwatched PID {pid}")
                
                for container_id in containers:
                    watched_containers.discard(container_id)
                    log(f"unwatched container {container_id}")
                
                result = {
                    "status": "ok",
                    "watched_pids": list(watched_pids),
                    "watched_containers": list(watched_containers),
                }
            
            self.send_json(200, result)
        
        else:
            self.send_json(404, {"error": "not found"})


def main():
    parser = argparse.ArgumentParser(description="DeadmanSwitch watchdog server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on")
    args = parser.parse_args()
    
    # Check if we should be disabled
    if os.environ.get("MPC_KEEP_ENV") == "1":
        log("MPC_KEEP_ENV=1 is set, deadman switch disabled - exiting")
        sys.exit(0)
    
    # Start watchdog thread
    watchdog = threading.Thread(target=watchdog_thread, daemon=True)
    watchdog.start()
    
    # Start HTTP server
    server = HTTPServer(("127.0.0.1", args.port), DeadmanHandler)
    server.timeout = 1  # Allow checking shutdown_event periodically
    
    log(f"listening on 127.0.0.1:{args.port}")
    log(f"ping timeout: {PING_TIMEOUT_SECONDS}s, check interval: {CHECK_INTERVAL_SECONDS}s")
    
    try:
        while not shutdown_event.is_set():
            server.handle_request()
    except KeyboardInterrupt:
        log("interrupted, shutting down")
    
    server.server_close()
    log("shutdown complete")


if __name__ == "__main__":
    main()
