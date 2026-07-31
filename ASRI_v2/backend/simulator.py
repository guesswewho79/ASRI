"""政务外网攻击面仿真数据生成器。

数据不是论文原始数据，而是用于真实算法训练和演示的可控仿真数据。
"""
from __future__ import annotations

import math
import random
from collections import defaultdict, deque
from typing import Dict, List, Any, Set, Tuple

NODE_TYPES = ["host", "service", "vulnerability", "account"]
REL_TYPES = ["DEPENDS_ON", "HAS_SERVICE", "HAS_VULN", "HAS_ACCESS"]
NODE_TYPE_TO_ID = {name: idx for idx, name in enumerate(NODE_TYPES)}
REL_TYPE_TO_ID = {name: idx for idx, name in enumerate(REL_TYPES)}
FEATURE_DIM = 16


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def generate_network(
    host_count: int = 100,
    seed: int = 20260731,
    vuln_density: float = 2.2,
    topology: str = "hierarchy",
) -> Dict[str, Any]:
    rng = random.Random(seed)
    host_count = max(30, min(800, int(host_count)))
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    entry_count = max(4, round(host_count * 0.08))
    core_count = max(4, round(host_count * 0.10))

    host_indices: List[int] = []
    entry_hosts: List[int] = []
    target_hosts: List[int] = []

    os_pool = [
        ("Windows Server 2019", 0.24),
        ("Windows Server 2022", 0.20),
        ("CentOS 7", 0.18),
        ("Ubuntu Server 22.04", 0.17),
        ("Windows 10", 0.12),
        ("国产服务器操作系统", 0.09),
    ]

    def sample_os() -> str:
        r = rng.random()
        acc = 0.0
        for name, weight in os_pool:
            acc += weight
            if r <= acc:
                return name
        return os_pool[0][0]

    def add_node(node: Dict[str, Any]) -> int:
        node["index"] = len(nodes)
        nodes.append(node)
        return node["index"]

    def add_edge(source: int, target: int, rel_type: str, **extra: Any) -> None:
        if source == target:
            return
        edge = {
            "id": f"E-{len(edges) + 1}",
            "source": int(source),
            "target": int(target),
            "type": rel_type,
            "type_id": REL_TYPE_TO_ID[rel_type],
            "disabled": False,
        }
        edge.update(extra)
        edges.append(edge)

    for i in range(host_count):
        is_entry = i < entry_count
        is_target = i >= host_count - core_count
        level = 0 if is_entry else (2 if is_target else 1)
        business = 8 + rng.randint(0, 2) if is_target else (4 + rng.randint(0, 3) if is_entry else 3 + rng.randint(0, 5))
        idx = add_node({
            "id": f"H-{i + 1:04d}",
            "label": ("边界接入" if is_entry else "核心业务" if is_target else "部门业务") + f"-{i + 1}",
            "type": "host",
            "type_id": NODE_TYPE_TO_ID["host"],
            "level": level,
            "os": sample_os(),
            "business_value": business,
            "is_entry": is_entry,
            "is_target": is_target,
            "resource_types": rng.sample(["开放端口", "服务账号", "共享目录", "运维通道"], k=2),
            "neutralized": False,
            "acl": False,
            "risk_label": 0.0,
            "features": [0.0] * FEATURE_DIM,
        })
        host_indices.append(idx)
        if is_entry:
            entry_hosts.append(idx)
        if is_target:
            target_hosts.append(idx)

    middle = [i for i in host_indices if not nodes[i]["is_entry"] and not nodes[i]["is_target"]]
    cores = target_hosts[:]

    for pos, host_idx in enumerate(middle):
        add_edge(entry_hosts[pos % len(entry_hosts)], host_idx, "DEPENDS_ON", channel="政务外网路由")
        if topology in {"hierarchy", "mesh", "grid"} and rng.random() < 0.28:
            add_edge(rng.choice(entry_hosts), host_idx, "DEPENDS_ON", channel="冗余链路")
        if topology in {"grid", "mesh"} and pos + 1 < len(middle) and rng.random() < 0.20:
            add_edge(host_idx, middle[pos + 1], "DEPENDS_ON", channel="横向互联")

    for pos, core_idx in enumerate(cores):
        parent_count = 3 if topology == "star" else 2
        for p in range(parent_count):
            add_edge(middle[(pos * 3 + p * 7 + rng.randint(0, 5)) % len(middle)], core_idx, "DEPENDS_ON", channel="核心交换")
        if topology == "mesh" and pos > 0:
            add_edge(cores[pos - 1], core_idx, "DEPENDS_ON", channel="核心互联")

    services_by_host: Dict[int, List[int]] = defaultdict(list)
    vulns_by_host: Dict[int, List[int]] = defaultdict(list)
    vuln_counter = 1

    service_pool = [
        ("Web政务服务", 443, "HTTPS"),
        ("统一身份认证", 8443, "HTTPS"),
        ("数据交换服务", 7001, "TCP"),
        ("文件共享服务", 445, "SMB"),
        ("数据库服务", 1521, "TCP"),
        ("运维管理服务", 22, "SSH"),
        ("消息中间件", 61616, "TCP"),
    ]

    for host_idx in host_indices:
        host = nodes[host_idx]
        account_idx = add_node({
            "id": f"A-{host_idx + 1:04d}",
            "label": rng.choice(["业务管理员", "运维账号", "审计账号", "服务账号"]),
            "type": "account",
            "type_id": NODE_TYPE_TO_ID["account"],
            "host_index": host_idx,
            "privilege": "高权限" if rng.random() < 0.18 else "普通权限",
            "risk_label": 0.0,
            "features": [0.0] * FEATURE_DIM,
        })
        add_edge(account_idx, host_idx, "HAS_ACCESS")

        service_count = 1 + (1 if rng.random() < 0.22 else 0)
        for s in range(service_count):
            service_name, port, protocol = rng.choice(service_pool)
            service_idx = add_node({
                "id": f"S-{host_idx + 1:04d}-{s + 1}",
                "label": service_name,
                "type": "service",
                "type_id": NODE_TYPE_TO_ID["service"],
                "host_index": host_idx,
                "port": port,
                "protocol": protocol,
                "exposed": bool(host["is_entry"] or rng.random() < 0.42),
                "risk_label": 0.0,
                "features": [0.0] * FEATURE_DIM,
            })
            services_by_host[host_idx].append(service_idx)
            add_edge(host_idx, service_idx, "HAS_SERVICE", port=port, protocol=protocol)

            expected = vuln_density / service_count
            vuln_count = int(expected) + (1 if rng.random() < expected % 1 else 0)
            if host["is_entry"] and rng.random() < 0.48:
                vuln_count += 1
            vuln_count = min(5, vuln_count)

            for _ in range(vuln_count):
                cvss = round(_clamp(rng.gauss(6.2 + (0.5 if host["is_entry"] else 0.0), 1.7), 2.5, 10.0), 1)
                epss = round(_clamp(cvss / 12 + rng.gauss(0.0, 0.14), 0.01, 0.98), 3)
                kev = bool(cvss >= 8.4 and rng.random() < 0.20)
                severity = "严重" if cvss >= 9 else "高危" if cvss >= 7 else "中危" if cvss >= 4 else "低危"
                vuln_idx = add_node({
                    "id": f"V-{vuln_counter:05d}",
                    "label": f"SIM-CVE-{rng.randint(2022, 2024)}-{1000 + vuln_counter}",
                    "type": "vulnerability",
                    "type_id": NODE_TYPE_TO_ID["vulnerability"],
                    "host_index": host_idx,
                    "service_index": service_idx,
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "severity": severity,
                    "patched": False,
                    "risk_label": 0.0,
                    "features": [0.0] * FEATURE_DIM,
                })
                vulns_by_host[host_idx].append(vuln_idx)
                add_edge(service_idx, vuln_idx, "HAS_VULN", cvss=cvss, severity=severity)
                vuln_counter += 1

    # 计算度数、特征和弱监督风险标签。
    degree = defaultdict(int)
    for edge in edges:
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1

    for idx, node in enumerate(nodes):
        features = [0.0] * FEATURE_DIM
        features[0] = node["type_id"] / max(1, len(NODE_TYPES) - 1)
        features[1] = min(1.0, degree[idx] / 12.0)
        if node["type"] == "host":
            vulns = [nodes[v] for v in vulns_by_host.get(idx, []) if not nodes[v].get("patched", False)]
            max_cvss = max((v["cvss"] for v in vulns), default=0.0) / 10.0
            max_epss = max((v["epss"] for v in vulns), default=0.0)
            has_kev = float(any(v["kev"] for v in vulns))
            features[2] = node["business_value"] / 10.0
            features[3] = float(node["is_entry"])
            features[4] = float(node["is_target"])
            features[5] = min(1.0, len(vulns) / 6.0)
            features[6] = max_cvss
            features[7] = max_epss
            features[8] = has_kev
            node["risk_label"] = _clamp(0.34 * max_cvss + 0.22 * max_epss + 0.10 * has_kev + 0.18 * node["business_value"] / 10 + 0.10 * float(node["is_entry"]) + 0.06 * features[1])
        elif node["type"] == "service":
            features[2] = node["port"] / 65535.0
            features[3] = float(node["exposed"])
            host_vulns = [nodes[v] for v in vulns_by_host.get(node["host_index"], [])]
            node["risk_label"] = _clamp(max((v["cvss"] / 10 for v in host_vulns), default=0.05) * 0.72 + 0.16 * float(node["exposed"]))
        elif node["type"] == "vulnerability":
            features[2] = node["cvss"] / 10.0
            features[3] = node["epss"]
            features[4] = float(node["kev"])
            features[5] = {"低危": 0.2, "中危": 0.45, "高危": 0.72, "严重": 1.0}[node["severity"]]
            node["risk_label"] = _clamp(0.68 * node["cvss"] / 10 + 0.25 * node["epss"] + 0.07 * float(node["kev"]))
        else:
            features[2] = float(node["privilege"] == "高权限")
            features[3] = float("服务" in node["label"])
            node["risk_label"] = 0.62 if node["privilege"] == "高权限" else 0.34
        node["features"] = [round(float(x), 6) for x in features]

    return {
        "meta": {
            "name": f"ASRI v2仿真网络-{host_count}主机",
            "host_count": host_count,
            "seed": seed,
            "vuln_density": vuln_density,
            "topology": topology,
            "feature_dim": FEATURE_DIM,
            "node_types": NODE_TYPES,
            "relation_types": REL_TYPES,
        },
        "nodes": nodes,
        "edges": edges,
        "host_indices": host_indices,
        "entry_hosts": entry_hosts,
        "target_hosts": target_hosts,
    }


def enumerate_attack_paths(graph: Dict[str, Any], max_length: int = 5, max_paths: int = 5000) -> List[List[int]]:
    host_set = set(graph["host_indices"])
    traversable = {i for i in host_set if not graph["nodes"][i].get("neutralized", False)}
    adjacency: Dict[int, List[int]] = {i: [] for i in host_set}
    for edge in graph["edges"]:
        if edge.get("disabled") or edge["type"] != "DEPENDS_ON":
            continue
        source, target = edge["source"], edge["target"]
        if source in traversable and target in traversable:
            adjacency[source].append(target)

    paths: List[List[int]] = []
    current: List[int] = []
    visited: Set[int] = set()
    targets = set(graph["target_hosts"])

    def dfs(node_idx: int, depth: int) -> None:
        if len(paths) >= max_paths or node_idx not in traversable:
            return
        current.append(node_idx)
        visited.add(node_idx)
        if node_idx in targets and len(current) >= 2:
            paths.append(current.copy())
        if depth < max_length:
            for nxt in adjacency.get(node_idx, []):
                if nxt not in visited:
                    dfs(nxt, depth + 1)
                if len(paths) >= max_paths:
                    break
        visited.remove(node_idx)
        current.pop()

    for entry in graph["entry_hosts"]:
        dfs(entry, 1)
        if len(paths) >= max_paths:
            break
    return paths


def analyze_graph(graph: Dict[str, Any], max_length: int = 5, max_paths: int = 5000) -> Dict[str, Any]:
    paths = enumerate_attack_paths(graph, max_length=max_length, max_paths=max_paths)
    hosts = [graph["nodes"][i] for i in graph["host_indices"]]
    active_vulns = [n for n in graph["nodes"] if n["type"] == "vulnerability" and not n.get("patched", False)]
    risks = sorted((h["risk_label"] for h in hosts), reverse=True)
    return {
        "paths": paths,
        "path_count": len(paths),
        "metrics": {
            "asset_count": len(hosts),
            "node_count": len(graph["nodes"]),
            "edge_count": sum(1 for e in graph["edges"] if not e.get("disabled")),
            "vulnerability_count": len(active_vulns),
            "kev_count": sum(1 for v in active_vulns if v.get("kev")),
            "max_cvss": max((v["cvss"] for v in active_vulns), default=0.0),
            "max_risk": round(risks[0] if risks else 0.0, 4),
            "avg_risk": round(sum(risks) / max(1, len(risks)), 4),
            "high_risk_assets": sum(1 for h in hosts if h["risk_label"] >= 0.65),
        },
        "top_assets": sorted(hosts, key=lambda n: n["risk_label"], reverse=True)[:20],
    }
