"""确定性MDP环境：攻击面收敛决策。"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple

import numpy as np
import torch

from gat_model import RelationAwareGAT, graph_to_tensors
from simulator import analyze_graph

OBS_DIM = 32


class AttackSurfaceEnv:
    def __init__(
        self,
        graph: Dict[str, Any],
        gat_model: RelationAwareGAT,
        max_steps: int = 20,
        max_path_length: int = 5,
        max_paths: int = 3000,
        local_view_k: int = 2,
        device: str = "cpu",
    ):
        self.base_graph = copy.deepcopy(graph)
        self.graph = copy.deepcopy(graph)
        self.gat = gat_model.to(device)
        self.gat.eval()
        self.max_steps = int(max_steps)
        self.max_path_length = int(max_path_length)
        self.max_paths = int(max_paths)
        self.local_view_k = int(local_view_k)
        self.device = device
        self.step_count = 0
        self.actions: List[Dict[str, Any]] = []
        self.action_history: List[Dict[str, Any]] = []
        self.initial_path_count = 0
        self.current_analysis: Dict[str, Any] = {}
        self.initial_analysis: Dict[str, Any] = {}
        self.last_risks: torch.Tensor | None = None

    def reset(self) -> np.ndarray:
        self.graph = copy.deepcopy(self.base_graph)
        self.step_count = 0
        self.action_history = []
        self.initial_analysis = analyze_graph(self.graph, self.max_path_length, self.max_paths)
        self.current_analysis = self.initial_analysis
        self.initial_path_count = max(1, self.initial_analysis["path_count"])
        self.actions = self._build_actions()
        return self._observe()

    @property
    def action_count(self) -> int:
        return len(self.actions)

    def _build_actions(self) -> List[Dict[str, Any]]:
        analysis = self.current_analysis
        host_path_count = {i: 0 for i in self.graph["host_indices"]}
        edge_path_count: Dict[Tuple[int, int], int] = {}
        for path in analysis["paths"]:
            for node_idx in path:
                host_path_count[node_idx] = host_path_count.get(node_idx, 0) + 1
            for i in range(len(path) - 1):
                key = (path[i], path[i + 1])
                edge_path_count[key] = edge_path_count.get(key, 0) + 1

        candidates: List[Dict[str, Any]] = []
        for idx, node in enumerate(self.graph["nodes"]):
            if node["type"] == "vulnerability" and not node.get("patched", False):
                host_idx = node.get("host_index")
                host = self.graph["nodes"][host_idx]
                candidates.append({
                    "id": f"patch-{idx}",
                    "type": "patch",
                    "target": idx,
                    "host_index": host_idx,
                    "label": f"修复{node['label']}",
                    "cost": 1.0,
                    "cvss": node["cvss"] / 10.0,
                    "epss": node["epss"],
                    "kev": float(node["kev"]),
                    "business": host["business_value"] / 10.0,
                    "paths_through": host_path_count.get(host_idx, 0),
                })

        for edge in self.graph["edges"]:
            if edge["type"] != "DEPENDS_ON" or edge.get("disabled"):
                continue
            key = (edge["source"], edge["target"])
            if edge_path_count.get(key, 0) <= 0:
                continue
            source = self.graph["nodes"][edge["source"]]
            target = self.graph["nodes"][edge["target"]]
            candidates.append({
                "id": f"segment-{edge['id']}",
                "type": "segment",
                "target": edge["id"],
                "host_index": edge["target"],
                "label": f"切断{source['label']}到{target['label']}的依赖",
                "cost": 1.4,
                "cvss": max(source["risk_label"], target["risk_label"]),
                "epss": max(source["risk_label"], target["risk_label"]) * 0.72,
                "kev": 0.0,
                "business": target["business_value"] / 10.0,
                "paths_through": edge_path_count[key],
            })

        for host_idx in self.graph["host_indices"]:
            host = self.graph["nodes"][host_idx]
            if host.get("acl") or (host_path_count.get(host_idx, 0) <= 0 and not host.get("is_entry")):
                continue
            candidates.append({
                "id": f"acl-{host_idx}",
                "type": "acl",
                "target": host_idx,
                "host_index": host_idx,
                "label": f"收紧{host['label']}访问控制",
                "cost": 0.8,
                "cvss": host["risk_label"],
                "epss": host["risk_label"] * 0.65,
                "kev": 0.0,
                "business": host["business_value"] / 10.0,
                "paths_through": host_path_count.get(host_idx, 0),
            })

        # 控制动作空间，优先保留路径覆盖高和风险高的候选。
        candidates.sort(key=lambda item: (item["paths_through"], item["cvss"], item["business"]), reverse=True)
        return candidates[:160]

    def _gat_risks(self) -> torch.Tensor:
        tensors = graph_to_tensors(self.graph, device=self.device)
        with torch.no_grad():
            output = self.gat(tensors["features"], tensors["node_types"], tensors["edge_index"], tensors["edge_type"])
        return output["risk"].detach().cpu()

    def _observe(self) -> np.ndarray:
        risks = self._gat_risks()
        self.last_risks = risks
        host_indices = self.graph["host_indices"]
        host_risks = risks[host_indices]
        hosts = [self.graph["nodes"][i] for i in host_indices]
        active_vulns = [n for n in self.graph["nodes"] if n["type"] == "vulnerability" and not n.get("patched", False)]
        active_edges = [e for e in self.graph["edges"] if not e.get("disabled")]
        top_risks = torch.sort(host_risks, descending=True).values[:12].tolist()
        top_risks += [0.0] * (12 - len(top_risks))
        path_ratio = self.current_analysis["path_count"] / max(1, self.initial_path_count or self.max_paths)
        obs = [
            float(host_risks.mean()) if len(host_risks) else 0.0,
            float(host_risks.max()) if len(host_risks) else 0.0,
            float(host_risks.std(unbiased=False)) if len(host_risks) else 0.0,
            max((h["business_value"] / 10 for h in hosts), default=0.0),
            sum(h["business_value"] for h in hosts) / max(1, len(hosts)) / 10,
            len(active_vulns) / max(1, len(self.graph["nodes"])),
            max((v["cvss"] for v in active_vulns), default=0.0) / 10,
            max((v["epss"] for v in active_vulns), default=0.0),
            sum(1 for v in active_vulns if v.get("kev")) / max(1, len(active_vulns)),
            path_ratio,
            len(active_edges) / max(1, len(self.graph["edges"])),
            sum(1 for n in self.graph["nodes"] if n.get("patched")) / max(1, len(self.graph["nodes"])),
            sum(1 for h in hosts if h.get("acl")) / max(1, len(hosts)),
            self.step_count / max(1, self.max_steps),
            self.local_view_k / 3.0,
            float(self.action_count) / 160.0,
        ] + top_risks
        obs = obs[:OBS_DIM] + [0.0] * max(0, OBS_DIM - len(obs))
        return np.asarray(obs, dtype=np.float32)

    def action_mask(self) -> np.ndarray:
        mask = np.ones(self.action_count, dtype=bool)
        for i, action in enumerate(self.actions):
            if action["type"] == "patch" and self.graph["nodes"][action["target"]].get("patched"):
                mask[i] = False
            elif action["type"] == "segment":
                edge = next((e for e in self.graph["edges"] if e["id"] == action["target"]), None)
                if edge is None or edge.get("disabled"):
                    mask[i] = False
            elif action["type"] == "acl" and self.graph["nodes"][action["target"]].get("acl"):
                mask[i] = False
            elif action["paths_through"] <= 0 and action["type"] != "patch":
                mask[i] = False
        return mask

    def _apply(self, action: Dict[str, Any]) -> None:
        if action["type"] == "patch":
            vuln = self.graph["nodes"][action["target"]]
            vuln["patched"] = True
            vuln["risk_label"] = 0.0
            host_idx = action["host_index"]
            active = [n for n in self.graph["nodes"] if n["type"] == "vulnerability" and n.get("host_index") == host_idx and not n.get("patched")]
            if not active:
                self.graph["nodes"][host_idx]["neutralized"] = True
        elif action["type"] == "segment":
            for edge in self.graph["edges"]:
                if edge["id"] == action["target"]:
                    edge["disabled"] = True
                    break
        elif action["type"] == "acl":
            host = self.graph["nodes"][action["target"]]
            host["acl"] = True
            host["neutralized"] = True

    def step(self, action_index: int) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        if action_index < 0 or action_index >= self.action_count or not self.action_mask()[action_index]:
            return self._observe(), -0.15, False, {"invalid": True}

        before_paths = self.current_analysis["path_count"]
        before_max_cvss = self.current_analysis["metrics"]["max_cvss"]
        action = self.actions[action_index]
        self._apply(action)
        self.current_analysis = analyze_graph(self.graph, self.max_path_length, self.max_paths)
        after_paths = self.current_analysis["path_count"]
        after_max_cvss = self.current_analysis["metrics"]["max_cvss"]
        self.step_count += 1

        delta_paths = max(0, before_paths - after_paths) / max(1, self.initial_path_count)
        threat = min(1.6, action["epss"] * (1 + float(action["kev"]))) / 1.6
        defense = max(0.0, before_max_cvss - after_max_cvss) / 10.0
        reward = 0.32 * action["cvss"] + 0.18 * threat + 0.16 * action["business"] + 2.2 * delta_paths + 0.30 * defense - 0.025 * action["cost"]
        reward = float(max(-1.0, min(3.0, reward)))

        asri = 1 - after_paths / max(1, self.initial_path_count)
        done = self.step_count >= self.max_steps or asri >= 0.98 or not self.action_mask().any()
        info = {
            "action": action,
            "asri": asri,
            "path_count": after_paths,
            "delta_paths": delta_paths,
            "step": self.step_count,
        }
        self.action_history.append({
            "step": self.step_count,
            "type": action["type"],
            "label": action["label"],
            "cost": action["cost"],
            "reward": round(reward, 4),
            "remaining_paths": after_paths,
            "asri": round(asri, 4),
        })
        return self._observe(), reward, done, info

    def summary(self) -> Dict[str, Any]:
        final_paths = self.current_analysis["path_count"]
        asri = 1 - final_paths / max(1, self.initial_path_count)
        return {
            "initial_paths": self.initial_path_count,
            "final_paths": final_paths,
            "asri": round(max(0.0, min(1.0, asri)), 4),
            "operations": len(self.action_history),
            "convergence_steps": len(self.action_history),
            "actions": self.action_history,
        }
