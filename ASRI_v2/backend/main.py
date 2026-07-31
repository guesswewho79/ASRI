"""ASRI v2真实算法后端API服务。"""
from __future__ import annotations

import os
import threading
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from gat_model import RelationAwareGAT
from mdp_env import AttackSurfaceEnv
from simulator import analyze_graph, generate_network
from training import ensure_dir, infer_with_ppo, train_gat, train_ppo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "models"))
ensure_dir(MODEL_DIR)

app = FastAPI(title="ASRI真实算法后端", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateSessionRequest(BaseModel):
    host_count: int = Field(default=100, ge=30, le=800)
    seed: int = 20260731
    vuln_density: float = Field(default=2.2, ge=0.5, le=6.0)
    topology: str = "hierarchy"
    hidden_dim: int = Field(default=64, ge=32, le=256)
    gat_layers: int = Field(default=2, ge=1, le=4)
    attention_heads: int = Field(default=4, ge=1, le=16)
    max_path_length: int = Field(default=5, ge=2, le=7)
    max_paths: int = Field(default=3000, ge=500, le=20000)
    max_steps: int = Field(default=16, ge=5, le=60)
    local_view_k: int = Field(default=2, ge=1, le=3)


class TrainGATRequest(BaseModel):
    epochs: int = Field(default=40, ge=5, le=300)
    learning_rate: float = Field(default=3e-4, gt=0, le=0.01)


class TrainPPORequest(BaseModel):
    episodes: int = Field(default=24, ge=4, le=300)
    learning_rate: float = Field(default=3e-4, gt=0, le=0.01)
    gamma: float = Field(default=0.95, ge=0.8, le=0.999)
    gae_lambda: float = Field(default=0.95, ge=0.8, le=0.999)
    clip: float = Field(default=0.2, ge=0.05, le=0.5)
    update_every: int = Field(default=4, ge=1, le=20)
    ppo_epochs: int = Field(default=4, ge=1, le=12)


class ConvergeRequest(BaseModel):
    max_steps: Optional[int] = Field(default=None, ge=1, le=80)


class SessionStore:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()

    def create_job(self, session_id: str, job_type: str) -> Dict[str, Any]:
        with self.lock:
            job_id = uuid.uuid4().hex[:12]
            job = {
                "job_id": job_id,
                "session_id": session_id,
                "type": job_type,
                "status": "pending",
                "created_at": time.time(),
                "started_at": None,
                "finished_at": None,
                "progress": 0,
                "logs": [],
                "result": None,
                "error": None,
            }
            self.jobs[job_id] = job
            return job

    def append_log(self, job_id: str, payload: Dict[str, Any]) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job["logs"].append({"time": time.time(), **payload})
            if len(job["logs"]) > 500:
                job["logs"] = job["logs"][-500:]
            if payload.get("type") == "progress":
                job["progress"] = round(100 * payload.get("epoch", 0) / max(1, payload.get("epochs", 1)), 1)
            elif payload.get("type") == "episode":
                total = payload.get("episodes_total")
                if total:
                    job["progress"] = round(100 * payload.get("episode", 0) / total, 1)

    def update_job(self, job_id: str, **updates: Any) -> None:
        with self.lock:
            self.jobs[job_id].update(updates)


store = SessionStore()


def get_session(session_id: str) -> Dict[str, Any]:
    with store.lock:
        session = store.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在，请先创建算法会话")
    return session


def run_job(job_id: str, fn) -> None:
    store.update_job(job_id, status="running", started_at=time.time())
    try:
        result = fn()
        store.update_job(job_id, status="completed", finished_at=time.time(), progress=100, result=result)
    except Exception as exc:
        traceback.print_exc()
        store.append_log(job_id, {"type": "error", "message": str(exc)})
        store.update_job(job_id, status="failed", finished_at=time.time(), error=str(exc))


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "name": "ASRI真实算法后端", "version": "2.0.0"}


@app.post("/api/v2/sessions")
def create_session(request: CreateSessionRequest) -> Dict[str, Any]:
    graph = generate_network(
        host_count=request.host_count,
        seed=request.seed,
        vuln_density=request.vuln_density,
        topology=request.topology,
    )
    analysis = analyze_graph(graph, request.max_path_length, request.max_paths)
    gat = RelationAwareGAT(hidden_dim=request.hidden_dim, layers=request.gat_layers, heads=request.attention_heads)
    session_id = uuid.uuid4().hex[:12]
    session = {
        "session_id": session_id,
        "config": request.model_dump(),
        "graph": graph,
        "initial_analysis": analysis,
        "gat": gat,
        "gat_trained": False,
        "gat_result": None,
        "ppo_agent": None,
        "ppo_result": None,
        "created_at": time.time(),
    }
    with store.lock:
        store.sessions[session_id] = session
    return {
        "session_id": session_id,
        "meta": graph["meta"],
        "metrics": analysis["metrics"],
        "path_count": analysis["path_count"],
        "top_assets": analysis["top_assets"][:10],
    }


@app.get("/api/v2/sessions/{session_id}")
def session_detail(session_id: str) -> Dict[str, Any]:
    session = get_session(session_id)
    analysis = analyze_graph(session["graph"], session["config"]["max_path_length"], session["config"]["max_paths"])
    return {
        "session_id": session_id,
        "config": session["config"],
        "meta": session["graph"]["meta"],
        "metrics": analysis["metrics"],
        "path_count": analysis["path_count"],
        "gat_trained": session["gat_trained"],
        "gat_result": session["gat_result"],
        "ppo_trained": session["ppo_agent"] is not None,
        "ppo_result": session["ppo_result"],
    }


@app.post("/api/v2/sessions/{session_id}/gat/train")
def start_gat_training(session_id: str, request: TrainGATRequest) -> Dict[str, Any]:
    session = get_session(session_id)
    job = store.create_job(session_id, "gat")

    def work() -> Dict[str, Any]:
        result = train_gat(
            session["gat"],
            session["graph"],
            epochs=request.epochs,
            lr=request.learning_rate,
            device="cpu",
            log_callback=lambda payload: store.append_log(job["job_id"], payload),
        )
        model_path = os.path.join(MODEL_DIR, f"gat_{session_id}.pt")
        session["gat"].save(model_path)
        session["gat_trained"] = True
        session["gat_result"] = result
        return {**result, "model_path": model_path}

    threading.Thread(target=run_job, args=(job["job_id"], work), daemon=True).start()
    return {"job_id": job["job_id"], "status": "pending"}


@app.post("/api/v2/sessions/{session_id}/ppo/train")
def start_ppo_training(session_id: str, request: TrainPPORequest) -> Dict[str, Any]:
    session = get_session(session_id)
    if not session["gat_trained"]:
        raise HTTPException(status_code=400, detail="请先完成GAT训练，再训练PPO")
    job = store.create_job(session_id, "ppo")

    def work() -> Dict[str, Any]:
        env = AttackSurfaceEnv(
            session["graph"],
            session["gat"],
            max_steps=session["config"]["max_steps"],
            max_path_length=session["config"]["max_path_length"],
            max_paths=session["config"]["max_paths"],
            local_view_k=session["config"]["local_view_k"],
            device="cpu",
        )

        def callback(payload: Dict[str, Any]) -> None:
            if payload.get("type") == "episode":
                payload = {**payload, "episodes_total": request.episodes}
            store.append_log(job["job_id"], payload)

        agent, result = train_ppo(
            env,
            episodes=request.episodes,
            lr=request.learning_rate,
            gamma=request.gamma,
            gae_lambda=request.gae_lambda,
            clip=request.clip,
            update_every=request.update_every,
            ppo_epochs=request.ppo_epochs,
            device="cpu",
            log_callback=callback,
        )
        model_path = os.path.join(MODEL_DIR, f"ppo_{session_id}.pt")
        agent.save(model_path)
        session["ppo_agent"] = agent
        session["ppo_result"] = result
        return {
            "episodes": result["episodes"],
            "best_asri": result["best_asri"],
            "best_total_reward": result["best_total_reward"],
            "last_policy_loss": result["last_policy_loss"],
            "last_value_loss": result["last_value_loss"],
            "model_path": model_path,
        }

    threading.Thread(target=run_job, args=(job["job_id"], work), daemon=True).start()
    return {"job_id": job["job_id"], "status": "pending"}


@app.get("/api/v2/jobs/{job_id}")
def job_detail(job_id: str) -> Dict[str, Any]:
    with store.lock:
        job = store.jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="任务不存在")
        return job


@app.post("/api/v2/sessions/{session_id}/converge")
def run_convergence(session_id: str, request: ConvergeRequest) -> Dict[str, Any]:
    session = get_session(session_id)
    if session["ppo_agent"] is None:
        raise HTTPException(status_code=400, detail="PPO模型尚未训练，无法执行真实算法收敛")
    env = AttackSurfaceEnv(
        session["graph"],
        session["gat"],
        max_steps=session["config"]["max_steps"],
        max_path_length=session["config"]["max_path_length"],
        max_paths=session["config"]["max_paths"],
        local_view_k=session["config"]["local_view_k"],
        device="cpu",
    )
    result = infer_with_ppo(env, session["ppo_agent"], max_steps=request.max_steps)
    final_analysis = analyze_graph(session["graph"], session["config"]["max_path_length"], session["config"]["max_paths"])
    return {
        "summary": result,
        "initial_metrics": session["initial_analysis"]["metrics"],
        "current_metrics": final_analysis["metrics"],
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8765, reload=False, log_level="info")
