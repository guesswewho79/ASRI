# 论文名称：[Research on Intelligent Prediction and Convergence of Attack Surface for Government Extranet]

## 简介
针对政务外网攻击面管理（Attack Surface Management, ASM）中暴露面识别不全面、收敛策略低效等核心挑战，提出一种融合图注意力网络（Graph Attention Network, GAT）与深度强化学习（Deep Reinforcement Learning, DRL）的攻击面智能预测与收敛框架，包含三个核心组件：基于GAT的多维度攻击面表示学习模块，融合资产类型、漏洞严重性和网络拓扑结构特征，实现攻击路径的高精度预测；基于确定性马尔可夫决策过程（Deterministic MDP）的收敛决策模型，支持收敛策略的动态生成；基于近端策略优化（Proximal Policy Optimization, PPO）的收敛策略优化算法，在局部观测约束下高效求解最优收敛序列。在参照政务外网组网特征构建的仿真网络环境（漏洞属性取自NVD真实数据）上的实验结果表明：所提完整模型的攻击面缩减指数（Attack Surface Reduction Index, ASRI）达到0.846，较GCN、GraphSAGE等基线方法提升14.2\%$\sim$17.0\%，与最优异构图基线性能相当；消融实验与参数敏感性分析验证了各模块的有效性和关键超参数的取值区间。该框架可为政务外网安全运营中的暴露面收敛提供智能化技术支撑。

## 环境要求
- Python 3.9+（如需配置训练模型）
- PyTorch 2.0+（如需配置训练模型）
- 实验在一台配备NVIDIA A100 GPU（40GB显存）的服务器上完成，软件环境为Ubuntu 20.04、PyTorch 2.1与PyTorch Geometric 2.4。在3,000节点实例上，完整训练500 epoch约需4$\sim$5小时；在留出的5,000节点测试实例上，单次推理约需150 ms。所有实验使用5个固定随机种子，文中结果均为5次独立运行的均值与标准差；

## 安装
```bash
git clone https://github.com/guesswewho79/ASRI.git
cd 仓库名
pip install -r requirements.txt# ASRI

## GitHub仓库目录结构
ASRI/
├── package.json
├── README.md
├── data/
│   └── 导入示例.json
├── scripts/
│   └── build-windows.ps1
├── assets/
└── src/
    ├── main.js
    ├── preload.js
    ├── index.html
    ├── styles.css
    ├── app.js
    └── engine.js
