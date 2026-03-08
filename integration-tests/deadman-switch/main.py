import asyncio
import os
import signal
import time
from typing import List, Set

import psutil
import uvicorn
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI()

# Global state
managed_pids: Set[int] = set()
last_ping_time: float = time.time()
DEADMAN_TIMEOUT = float(os.getenv("DEADMAN_TIMEOUT", 60.0))

class RegisterRequest(BaseModel):
    pids: List[int]

@app.on_event("startup")
async def startup_event():
    # Start the monitoring task
    asyncio.create_task(monitor_deadman())

async def monitor_deadman():
    global last_ping_time, managed_pids
    print(f"Deadman switch started with timeout {DEADMAN_TIMEOUT}s")
    while True:
        await asyncio.sleep(1)
        elapsed = time.time() - last_ping_time
        if elapsed > DEADMAN_TIMEOUT:
            print(f"Timeout reached ({elapsed:.2f}s > {DEADMAN_TIMEOUT}s). Killing processes...")
            await kill_processes()
            # Reset state effectively (or just keep waiting? The service might be done)
            # We clear PIDs so we don't try to kill them again.
            managed_pids.clear()
            # Reset timer to avoid spamming kills if the service stays up?
            # Or usually the integration test would kill this service too.
            # But let's just reset time to "now" to give another grace period if reused.
            last_ping_time = time.time()

async def kill_processes():
    global managed_pids
    if not managed_pids:
        return

    print(f"Killing {len(managed_pids)} processes: {managed_pids}")
    for pid in managed_pids:
        try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                process.terminate() # SIGTERM
                # Give a small grace period then SIGKILL?
                # For simplicity, just terminate. psutil.kill() is SIGKILL.
                # integration-tests usually prefer kill to be sure.
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Wait a bit and force kill if needed?
    # For this implementation, we'll iterate again with kill() if we want to be super sure,
    # but let's stick to terminate for now and maybe upgrade to kill if requested.
    # Actually, let's use kill() (SIGKILL) to ensure no zombies.
    for pid in managed_pids:
         try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                process.kill()
         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

@app.post("/register")
async def register(req: RegisterRequest):
    global managed_pids
    for pid in req.pids:
        managed_pids.add(pid)
    return {"status": "registered", "count": len(managed_pids)}

@app.post("/ping")
async def ping():
    global last_ping_time
    last_ping_time = time.time()
    return {"status": "pong"}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
