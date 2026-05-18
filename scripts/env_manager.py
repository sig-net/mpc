#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = ROOT / "target"
STATE_FILE = TARGET_DIR / "mpc-dev-env-manager.json"
RUNTIME_STATE_FILE = TARGET_DIR / "mpc-dev-env.json"
SOCKET_FILE = TARGET_DIR / "mpc-dev-env.sock"
PID_FILE = TARGET_DIR / "mpc-dev-env.pid"
LOG_FILE = TARGET_DIR / "mpc-dev-env.log"


def ensure_target() -> None:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)


def parse_nodes_threshold(argv: list[str]) -> tuple[int, int]:
    if len(argv) < 1 or len(argv) > 2:
        raise SystemExit("usage: start <nodes> [threshold]")
    nodes_arg = argv[0]
    if not nodes_arg.endswith("n") or not nodes_arg[:-1].isdigit():
        raise SystemExit(f"expected node count like 8n, got: {nodes_arg}")
    nodes = int(nodes_arg[:-1])
    if len(argv) == 2:
        threshold_arg = argv[1]
        if not threshold_arg.endswith("t") or not threshold_arg[:-1].isdigit():
            raise SystemExit(f"expected threshold like 4t, got: {threshold_arg}")
        threshold = int(threshold_arg[:-1])
    else:
        threshold = nodes // 2 + 1
    return nodes, threshold


def load_state() -> dict[str, Any] | None:
    if not STATE_FILE.exists():
        return None
    return json.loads(STATE_FILE.read_text())


def save_state(state: dict[str, Any]) -> None:
    ensure_target()
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))


def remove_runtime_files() -> None:
    for path in (SOCKET_FILE, PID_FILE):
        if path.exists():
            path.unlink()


def manager_running() -> bool:
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def send_command(payload: dict[str, Any]) -> dict[str, Any]:
    if not SOCKET_FILE.exists():
        raise SystemExit("environment manager is not running")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(SOCKET_FILE))
        client.sendall(json.dumps(payload).encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        response = client.recv(1 << 20)
    if not response:
        raise SystemExit("environment manager did not respond")
    data = json.loads(response.decode("utf-8"))
    if not data.get("ok", False):
        raise SystemExit(data.get("error", "request failed"))
    return data


def cargo_command(*args: str) -> list[str]:
    return ["cargo", "run", "-p", "integration-tests", "--", *args]


def start(argv: list[str]) -> None:
    ensure_target()
    if manager_running():
        raise SystemExit("environment manager is already running; use `just env status` or `just env kill` first")

    nodes, threshold = parse_nodes_threshold(argv)
    with LOG_FILE.open("ab") as log:
        process = subprocess.Popen(
            [sys.executable, __file__, "_serve", str(nodes), str(threshold)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    PID_FILE.write_text(str(process.pid))
    print(f"environment manager started with pid={process.pid}")
    print(f"log file: {LOG_FILE}")


def serve(nodes: int, threshold: int) -> int:
    ensure_target()
    remove_runtime_files()

    child_log = LOG_FILE.open("ab")
    child = subprocess.Popen(
        cargo_command(
            "setup-env",
            "--nodes",
            str(nodes),
            "--threshold",
            str(threshold),
            "--state-file",
            str(RUNTIME_STATE_FILE),
        ),
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=child_log,
        stderr=child_log,
        start_new_session=True,
    )

    state = {
        "started_at": time.time(),
        "nodes": nodes,
        "threshold": threshold,
        "manager_pid": os.getpid(),
        "child_pid": child.pid,
        "sign_requests": 0,
        "ready": False,
        "runtime_state_file": str(RUNTIME_STATE_FILE),
        "log_file": str(LOG_FILE),
    }
    save_state(state)
    PID_FILE.write_text(str(os.getpid()))

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET_FILE))
        server.listen()
        server.settimeout(1.0)

        while True:
            if not state["ready"] and RUNTIME_STATE_FILE.exists():
                state["ready"] = True
                save_state(state)

            exited = child.poll()
            if exited is not None:
                state["ready"] = False
                state["exited_at"] = time.time()
                state["exit_code"] = exited
                save_state(state)
                break

            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue

            with conn:
                raw = conn.recv(1 << 20)
                response = handle_request(state, child, raw)
                save_state(state)
                conn.sendall(json.dumps(response).encode("utf-8"))

    child_log.close()
    remove_runtime_files()
    return 0


def handle_request(state: dict[str, Any], child: subprocess.Popen[Any], raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
        command = payload["command"]
        if command == "status":
            now = time.time()
            return {
                "ok": True,
                "status": {
                    **state,
                    "uptime_seconds": round(now - state["started_at"], 1),
                },
            }
        if command == "kill":
            child.send_signal(signal.SIGINT)
            return {"ok": True, "message": "sent SIGINT to interactive environment"}
        if command == "sign":
            ensure_ready(state)
            run_helper(payload["args"])
            state["sign_requests"] += sign_request_count(payload["args"])
            return {"ok": True, "message": "sign request submitted"}
        if command == "reshare":
            ensure_ready(state)
            run_helper(payload["args"])
            return {"ok": True, "message": "reshare request submitted"}
        return {"ok": False, "error": f"unknown command: {command}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def ensure_ready(state: dict[str, Any]) -> None:
    if not state.get("ready"):
        raise RuntimeError("interactive environment is not ready yet")


def run_helper(args: list[str]) -> None:
    subprocess.run(
        cargo_command(*args, "--state-file", str(RUNTIME_STATE_FILE)),
        cwd=ROOT,
        check=True,
    )


def sign_request_count(args: list[str]) -> int:
    if "--multi" in args:
        idx = args.index("--multi")
        return int(args[idx + 1])
    return 1


def sign(argv: list[str]) -> None:
    if len(argv) == 0:
        args = ["invoke-sign"]
    elif argv[0] == "multi":
        if len(argv) != 2:
            raise SystemExit("usage: sign multi <count>")
        args = ["invoke-sign", "--multi", argv[1]]
    elif argv[0] == "bidirectional":
        args = ["invoke-sign", "--bidirectional"]
    elif len(argv) == 1:
        args = ["invoke-sign", "--tx-hash", argv[0]]
    else:
        raise SystemExit("usage: sign [tx_hash] | sign multi <count> | sign bidirectional")

    response = send_command({"command": "sign", "args": args})
    print(response["message"])


def reshare(argv: list[str]) -> None:
    if len(argv) < 1 or len(argv) > 2:
        raise SystemExit("usage: reshare join|kick [account_id]")
    action = argv[0]
    if action == "join":
        args = ["reshare", "join"]
    elif action == "kick":
        args = ["reshare", "kick"]
        if len(argv) == 2:
            args.extend(["--target", argv[1]])
    else:
        raise SystemExit(f"unknown reshare action: {action}")

    response = send_command({"command": "reshare", "args": args})
    print(response["message"])


def status() -> None:
    if not manager_running():
        print("environment manager is not running")
        if STATE_FILE.exists():
            last = load_state() or {}
            if last:
                print(f"last nodes: {last.get('nodes')}")
                print(f"last threshold: {last.get('threshold')}")
                print(f"last sign requests: {last.get('sign_requests')}")
                if "exit_code" in last:
                    print(f"last exit code: {last['exit_code']}")
        return

    response = send_command({"command": "status"})
    status = response["status"]
    print(f"manager pid: {status['manager_pid']}")
    print(f"environment pid: {status['child_pid']}")
    print(f"ready: {status['ready']}")
    print(f"uptime: {status['uptime_seconds']}s")
    print(f"nodes: {status['nodes']}")
    print(f"threshold: {status['threshold']}")
    print(f"sign requests: {status['sign_requests']}")
    print(f"log file: {status['log_file']}")


def kill() -> None:
    response = send_command({"command": "kill"})
    print(response["message"])


def main(argv: list[str]) -> int:
    if not argv:
        raise SystemExit("usage: env_manager.py start|status|kill|sign|reshare ...")

    command, *rest = argv
    if command == "start":
        start(rest)
        return 0
    if command == "_serve":
        if len(rest) != 2:
            raise SystemExit("usage: _serve <nodes> <threshold>")
        return serve(int(rest[0]), int(rest[1]))
    if command == "status":
        status()
        return 0
    if command == "kill":
        kill()
        return 0
    if command == "sign":
        sign(rest)
        return 0
    if command == "reshare":
        reshare(rest)
        return 0

    raise SystemExit(f"unknown command: {command}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
