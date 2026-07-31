"""纯PyTorch关系感知GAT模型。

不依赖PyTorch Geometric，直接使用边列表和index_add实现稀疏消息传递，
便于后续在Windows环境中打包和部署。
"""
from __future__ import annotations

from typing import Dict, Any, Tuple

import torch
from torch import nn
import torch.nn.functional as F

from simulator import NODE_TYPES, REL_TYPES, FEATURE_DIM


class RelationGATLayer(nn.Module):
    def __init__(self, in_dim: int, out_dim: int, heads: int = 8, relation_dim: int = 16, dropout: float = 0.15):
        super().__init__()
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.heads = heads
        self.relation_dim = relation_dim

        self.weight = nn.Parameter(torch.empty(in_dim, heads * out_dim))
        self.attention = nn.Parameter(torch.empty(heads, 2 * out_dim + relation_dim))
        self.relation_embedding = nn.Parameter(torch.empty(len(REL_TYPES), relation_dim))
        self.residual = nn.Identity() if in_dim == heads * out_dim else nn.Linear(in_dim, heads * out_dim, bias=False)
        self.dropout = nn.Dropout(dropout)
        self.reset_parameters()

    def reset_parameters(self) -> None:
        nn.init.xavier_uniform_(self.weight)
        nn.init.xavier_uniform_(self.attention)
        nn.init.xavier_uniform_(self.relation_embedding)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_type: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        node_count = x.size(0)
        h = torch.matmul(x, self.weight).view(node_count, self.heads, self.out_dim)
        source = edge_index[:, 0].long()
        target = edge_index[:, 1].long()
        rel = self.relation_embedding[edge_type.long()].unsqueeze(1).expand(-1, self.heads, -1)

        source_h = h[source]
        target_h = h[target]
        pair = torch.cat([source_h, target_h, rel], dim=-1)
        scores = F.leaky_relu((pair * self.attention.unsqueeze(0)).sum(dim=-1), negative_slope=0.2)

        max_scores = torch.full((node_count, self.heads), -1e9, device=x.device, dtype=scores.dtype)
        max_scores.scatter_reduce_(0, target.unsqueeze(-1).expand(-1, self.heads), scores, reduce="amax", include_self=True)
        exp_scores = torch.exp(scores - max_scores[target])
        denominator = torch.zeros(node_count, self.heads, device=x.device, dtype=scores.dtype)
        denominator.index_add_(0, target, exp_scores)
        alpha = exp_scores / (denominator[target] + 1e-9)
        alpha = self.dropout(alpha)

        messages = source_h * alpha.unsqueeze(-1)
        out = torch.zeros(node_count, self.heads, self.out_dim, device=x.device, dtype=h.dtype)
        out.index_add_(0, target, messages)
        out = out.reshape(node_count, self.heads * self.out_dim)
        return F.elu(out + self.residual(x)), alpha


class RelationAwareGAT(nn.Module):
    def __init__(
        self,
        feature_dim: int = FEATURE_DIM,
        hidden_dim: int = 64,
        layers: int = 2,
        heads: int = 4,
        dropout: float = 0.15,
    ):
        super().__init__()
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.layers_count = layers
        self.heads = heads

        self.type_projection = nn.ModuleList([
            nn.Linear(feature_dim, hidden_dim) for _ in NODE_TYPES
        ])
        self.input_norm = nn.LayerNorm(hidden_dim)
        self.gat_layers = nn.ModuleList()
        in_dim = hidden_dim
        for _ in range(layers):
            self.gat_layers.append(RelationGATLayer(in_dim, hidden_dim // heads, heads=heads, dropout=dropout))
            in_dim = hidden_dim
        self.output_norm = nn.LayerNorm(hidden_dim)
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, features: torch.Tensor, node_types: torch.Tensor, edge_index: torch.Tensor, edge_type: torch.Tensor) -> Dict[str, torch.Tensor]:
        projected = torch.zeros(features.size(0), self.hidden_dim, device=features.device, dtype=features.dtype)
        for type_id, projection in enumerate(self.type_projection):
            mask = node_types == type_id
            if mask.any():
                projected[mask] = projection(features[mask])
        h = self.input_norm(projected)
        attentions = []
        for layer in self.gat_layers:
            h, alpha = layer(h, edge_index, edge_type)
            attentions.append(alpha)
        h = self.output_norm(h)
        risk = torch.sigmoid(self.risk_head(h)).squeeze(-1)
        return {"embeddings": h, "risk": risk, "attention": attentions}

    def save(self, path: str) -> None:
        torch.save(self.state_dict(), path)

    @classmethod
    def load(cls, path: str, **kwargs: Any) -> "RelationAwareGAT":
        model = cls(**kwargs)
        model.load_state_dict(torch.load(path, map_location="cpu"))
        model.eval()
        return model


def graph_to_tensors(graph: Dict[str, Any], device: str = "cpu") -> Dict[str, torch.Tensor]:
    features = torch.tensor([node["features"] for node in graph["nodes"]], dtype=torch.float32, device=device)
    node_types = torch.tensor([node["type_id"] for node in graph["nodes"]], dtype=torch.long, device=device)
    active_edges = [edge for edge in graph["edges"] if not edge.get("disabled", False)]
    edge_index = torch.tensor([[edge["source"], edge["target"]] for edge in active_edges], dtype=torch.long, device=device)
    edge_type = torch.tensor([edge["type_id"] for edge in active_edges], dtype=torch.long, device=device)
    risk_labels = torch.tensor([node["risk_label"] for node in graph["nodes"]], dtype=torch.float32, device=device)
    return {
        "features": features,
        "node_types": node_types,
        "edge_index": edge_index,
        "edge_type": edge_type,
        "risk_labels": risk_labels,
    }
