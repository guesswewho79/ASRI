"""ASRI v2后端API快速冒烟测试。"""
from __future__ import annotations

import json
import time
import urllib.request

BASE = "http://127.0.0.1:8765"


def post(path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.loads(response.read().decode("utf-8"))


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_job(job_id: str) -> dict:
    while True:
        job = get(f"/api/v2/jobs/{job_id}")
        if job["status"] in {"completed", "failed"}:
            return job
        time.sleep(1)


def main() -> None:
    print("health:", get("/health"))
    session = post("/api/v2/sessions", {
        "host_count": 45,
        "seed": 20260731,
        "vuln_density": 1.8,
        "topology": "hierarchy",
        "hidden_dim": 64,
        "gat_layers": 2,
        "attention_heads": 4,
        "max_path_length": 5,
        "max_paths": 1500,
        "max_steps": 6,
        "local_view_k": 2,
    })
    session_id = session["session_id"]
    print("session:", session_id, session["metrics"])

    gat = post(f"/api/v2/sessions/{session_id}/gat/train", {"epochs": 5, "learning_rate": 0.0003})
    print("gat:", wait_job(gat["job_id"])["result"])

    ppo = post(f"/api/v2/sessions/{session_id}/ppo/train", {
        "episodes": 4,
        "learning_rate": 0.0003,
        "gamma": 0.95,
        "gae_lambda": 0.95,
        "clip": 0.2,
        "update_every": 2,
        "ppo_epochs": 2,
    })
    print("ppo:", wait_job(ppo["job_id"])["result"])

    result = post(f"/api/v2/sessions/{session_id}/converge", {"max_steps": 6})
    print("converge:", result["summary"])


if __name__ == "__main__":
    main()
