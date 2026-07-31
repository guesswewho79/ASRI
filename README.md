# ASRI：政务外网攻击面智能预测与收敛系统

本仓库用于复现论文《面向政务外网的攻击面智能预测与收敛研究》。

当前最新版本为 **ASRI v2.0**，源码位于：

```text
asri_v2/

v2.0主要内容
Electron桌面前端；
Python FastAPI本地后端；
纯PyTorch关系感知GAT；
确定性MDP环境；
Actor-Critic PPO；
GAE优势估计；
PPO Clip；
补丁部署、网络分段、访问控制收紧三类动作；
ASRI攻击面缩减指数；
Windows一键启动脚本。

进入源码目录：
cd asri_v2

一键启动：
.\scripts\start_all.ps1

详细运行教程请查看：
asri_v2/README.md

项目结构：
asri_v2/
├── backend/       # FastAPI、仿真攻击图、GAT、MDP、PPO
├── frontend/      # Electron桌面前端
├── models/        # 训练后的模型权重输出目录
├── experiments/   # 实验结果预留目录
├── scripts/       # Windows启动和API测试脚本
├── requirements.txt
└── README.md

复现边界：

## 10.3 提交README修改

页面拉到底部，提交信息填写：

```text
Update README for ASRI v2.0
