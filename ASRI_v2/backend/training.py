"""GAT与PPO训练逻辑。"""
from __future__ import annotations

import copy
import math
import os
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import torch
from torch import nn
import torch.nn.functional as F
from torch.distributions import Categorical

from gat_model import RelationAwareGAT, graph_to_tensors
from mdp_env import AttackSurfaceEnv, OBS_DIM

LogCallback = Optional[Callable[[Dict[str, Any]], None]]


def _log(callback: LogCallback, payload: Dict[str, Any]) -> None:
    if callback:
        callback(payload)


def train_gat(
    model: RelationAwareGAT,
    graph: Dict[str, Any],
    epochs: int = 40,
    lr: float = 3e-4,
    device: str = "cpu",
    log_callback: LogCallback = None,
) -> Dict[str, Any]:
    model.to(device)
    model.train()
    tensors = graph_to_tensors(graph, device=device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    host_indices = torch.tensor(graph["host_indices"], dtype=torch.long, device=device)

    for epoch in range(1, int(epochs) + 1):
        optimizer.zero_grad(set_to_none=True)
        output = model(tensors["features"], tensors["node_types"], tensors["edge_index"], tensors["edge_type"])
        risk = output["risk"]
        all_loss = F.mse_loss(risk, tensors["risk_labels"])
        host_loss = F.mse_loss(risk[host_indices], tensors["risk_labels"][host_indices])
        loss = all_loss + 1.5 * host_loss
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
        optimizer.step()

        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            mae = float(torch.mean(torch.abs(risk.detach() - tensors["risk_labels"])).cpu())
            _log(log_callback, {
                "type": "progress",
                "epoch": epoch,
                "epochs": epochs,
                "loss": round(float(loss.detach().cpu()), 6),
                "mae": round(mae, 6),
            })

    model.eval()
    with torch.no_grad():
        output = model(tensors["features"], tensors["node_types"], tensors["edge_index"], tensors["edge_type"])
        final_mae = float(torch.mean(torch.abs(output["risk"] - tensors["risk_labels"])).cpu())
    return {"epochs": epochs, "final_mae": round(final_mae, 6)}


class ActorCritic(nn.Module):
    def __init__(self, obs_dim: int = OBS_DIM, action_dim: int = 1, hidden_dim: int = 128):
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
        )
        self.actor = nn.Linear(hidden_dim, action_dim)
        self.critic = nn.Linear(hidden_dim, 1)
        self.reset_parameters()

    def reset_parameters(self) -> None:
        for layer in self.modules():
            if isinstance(layer, nn.Linear):
                nn.init.orthogonal_(layer.weight, gain=math.sqrt(2))
                nn.init.zeros_(layer.bias)
        nn.init.orthogonal_(self.actor.weight, gain=0.01)
        nn.init.orthogonal_(self.critic.weight, gain=1.0)

    def forward(self, obs: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        h = self.shared(obs)
        return self.actor(h), self.critic(h).squeeze(-1)


class PPOAgent:
    def __init__(self, action_dim: int, obs_dim: int = OBS_DIM, device: str = "cpu"):
        self.device = device
        self.model = ActorCritic(obs_dim=obs_dim, action_dim=action_dim).to(device)

    def _masked_logits(self, obs: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        logits, _ = self.model(obs)
        return logits.masked_fill(~mask.bool(), -1e9)

    def select_action(self, obs: np.ndarray, mask: np.ndarray, deterministic: bool = False):
        obs_t = torch.tensor(obs, dtype=torch.float32, device=self.device).unsqueeze(0)
        mask_t = torch.tensor(mask, dtype=torch.bool, device=self.device).unsqueeze(0)
        with torch.no_grad():
            logits, value = self.model(obs_t)
            logits = logits.masked_fill(~mask_t, -1e9)
            if deterministic:
                action = torch.argmax(logits, dim=-1)
                log_prob = F.log_softmax(logits, dim=-1).gather(1, action.unsqueeze(-1)).squeeze(-1)
            else:
                dist = Categorical(logits=logits)
                action = dist.sample()
                log_prob = dist.log_prob(action)
        return int(action.cpu().item()), float(log_prob.cpu().item()), float(value.squeeze(0).cpu().item())

    def save(self, path: str) -> None:
        torch.save(self.model.state_dict(), path)

    def load(self, path: str) -> None:
        self.model.load_state_dict(torch.load(path, map_location=self.device))
        self.model.eval()


def _compute_gae(rewards, values, dones, gamma: float, gae_lambda: float):
    advantages = []
    gae = 0.0
    next_value = 0.0
    for t in reversed(range(len(rewards))):
        non_terminal = 1.0 - float(dones[t])
        delta = rewards[t] + gamma * next_value * non_terminal - values[t]
        gae = delta + gamma * gae_lambda * non_terminal * gae
        advantages.insert(0, gae)
        next_value = values[t]
    returns = [adv + value for adv, value in zip(advantages, values)]
    return advantages, returns


def train_ppo(
    env: AttackSurfaceEnv,
    episodes: int = 24,
    lr: float = 3e-4,
    gamma: float = 0.95,
    gae_lambda: float = 0.95,
    clip: float = 0.2,
    update_every: int = 4,
    ppo_epochs: int = 4,
    device: str = "cpu",
    log_callback: LogCallback = None,
) -> tuple[PPOAgent, Dict[str, Any]]:
    obs = env.reset()
    agent = PPOAgent(action_dim=env.action_count, device=device)
    optimizer = torch.optim.Adam(agent.model.parameters(), lr=lr)

    memory: Dict[str, List[Any]] = {key: [] for key in ["obs", "actions", "log_probs", "rewards", "values", "dones", "masks"]}
    episode_summaries: List[Dict[str, Any]] = []
    update_count = 0
    last_policy_loss = 0.0
    last_value_loss = 0.0

    for episode in range(1, int(episodes) + 1):
        obs = env.reset()
        done = False
        total_reward = 0.0
        while not done:
            mask = env.action_mask()
            action, log_prob, value = agent.select_action(obs, mask, deterministic=False)
            next_obs, reward, done, info = env.step(action)
            memory["obs"].append(obs)
            memory["actions"].append(action)
            memory["log_probs"].append(log_prob)
            memory["rewards"].append(float(reward))
            memory["values"].append(value)
            memory["dones"].append(bool(done))
            memory["masks"].append(mask.copy())
            total_reward += float(reward)
            obs = next_obs

        summary = env.summary()
        summary.update({"episode": episode, "total_reward": round(total_reward, 4)})
        episode_summaries.append(summary)
        _log(log_callback, {"type": "episode", **summary})

        if episode % update_every == 0 or episode == episodes:
            obs_t = torch.tensor(np.asarray(memory["obs"]), dtype=torch.float32, device=device)
            actions_t = torch.tensor(memory["actions"], dtype=torch.long, device=device)
            old_log_probs_t = torch.tensor(memory["log_probs"], dtype=torch.float32, device=device)
            values_t = torch.tensor(memory["values"], dtype=torch.float32, device=device)
            masks_t = torch.tensor(np.asarray(memory["masks"]), dtype=torch.bool, device=device)
            advantages, returns = _compute_gae(memory["rewards"], memory["values"], memory["dones"], gamma, gae_lambda)
            advantages_t = torch.tensor(advantages, dtype=torch.float32, device=device)
            returns_t = torch.tensor(returns, dtype=torch.float32, device=device)
            if advantages_t.numel() > 1:
                advantages_t = (advantages_t - advantages_t.mean()) / (advantages_t.std(unbiased=False) + 1e-8)

            for _ in range(int(ppo_epochs)):
                logits, values_pred = agent.model(obs_t)
                logits = logits.masked_fill(~masks_t, -1e9)
                dist = Categorical(logits=logits)
                new_log_probs = dist.log_prob(actions_t)
                ratio = torch.exp(new_log_probs - old_log_probs_t)
                surrogate_1 = ratio * advantages_t
                surrogate_2 = torch.clamp(ratio, 1.0 - clip, 1.0 + clip) * advantages_t
                policy_loss = -torch.min(surrogate_1, surrogate_2).mean()
                value_loss = F.mse_loss(values_pred, returns_t)
                entropy = dist.entropy().mean()
                loss = policy_loss + 0.5 * value_loss - 0.01 * entropy

                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(agent.model.parameters(), max_norm=5.0)
                optimizer.step()
                last_policy_loss = float(policy_loss.detach().cpu())
                last_value_loss = float(value_loss.detach().cpu())

            update_count += 1
            memory = {key: [] for key in memory}
            _log(log_callback, {
                "type": "update",
                "episode": episode,
                "update": update_count,
                "policy_loss": round(last_policy_loss, 6),
                "value_loss": round(last_value_loss, 6),
            })

    best = max(episode_summaries, key=lambda item: (item["asri"], item["total_reward"])) if episode_summaries else {}
    result = {
        "episodes": episodes,
        "best_asri": best.get("asri", 0.0),
        "best_total_reward": best.get("total_reward", 0.0),
        "last_policy_loss": round(last_policy_loss, 6),
        "last_value_loss": round(last_value_loss, 6),
        "episode_summaries": episode_summaries,
    }
    return agent, result


def infer_with_ppo(env: AttackSurfaceEnv, agent: PPOAgent, max_steps: Optional[int] = None) -> Dict[str, Any]:
    obs = env.reset()
    done = False
    limit = min(max_steps or env.max_steps, env.max_steps)
    while not done and env.step_count < limit:
        mask = env.action_mask()
        action, _, _ = agent.select_action(obs, mask, deterministic=True)
        obs, reward, done, info = env.step(action)
        if info.get("invalid"):
            break
    return env.summary()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
