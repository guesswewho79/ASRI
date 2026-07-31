# 政务外网攻击面智能预测与收敛系统 v2.0

本项目根据论文《面向政务外网的攻击面智能预测与收敛研究》复现，提供可运行的前后端分离源码。v2.0在v1.0 Electron前端基础上新增Python本地算法后端，使用纯PyTorch实现关系感知GAT与PPO，不依赖PyTorch Geometric，适合在普通Windows电脑的CPU上进行小规模快速演示。预计将在2个月后发布GPU训练版本。

## 1. 已实现内容

### 前端

- Electron桌面界面；
- 攻击面运行总览；
- 异构攻击图可视化；
- 攻击路径分析；
- 收敛动作回放；
- 基线对比与敏感性分析；
- JSON数据导入和结果导出；
- “真实算法”页面，可连接Python后端、创建算法会话、启动训练、查看日志并运行PPO收敛推理。

### 后端

- FastAPI本地服务，默认地址：`http://127.0.0.1:8765`；
- 政务外网风格仿真攻击图生成；
- Host、Service、Vulnerability、Account四类节点；
- DEPENDS_ON、HAS_SERVICE、HAS_VULN、HAS_ACCESS四类关系；
- 深度受限攻击路径枚举；
- CVSS、EPSS、KEV、业务重要性、拓扑度等风险因子；
- 纯PyTorch关系感知GAT；
- 确定性MDP环境；
- Actor-Critic PPO；
- GAE优势估计；
- PPO Clip目标函数；
- 补丁部署、网络分段、访问控制收紧三类动作；
- ASRI攻击面缩减指数。

## 2. 项目结构

```text
asri_v2/
├── backend/
│   ├── main.py              # FastAPI服务与训练任务管理
│   ├── simulator.py         # 仿真网络、攻击图、路径枚举
│   ├── gat_model.py         # 纯PyTorch关系感知GAT
│   ├── mdp_env.py           # 确定性MDP收敛环境
│   ├── training.py          # GAT训练、PPO训练、GAE、推理
│   └── requirements.txt     # Python依赖
├── frontend/
│   ├── package.json         # Electron配置
│   ├── data/                # JSON导入示例
│   ├── scripts/             # Windows打包脚本
│   └── src/
│       ├── main.js          # Electron主进程
│       ├── preload.js       # 桌面能力桥接
│       ├── index.html       # 页面结构
│       ├── styles.css       # 页面样式
│       ├── engine.js        # v1轻量演示引擎
│       ├── app.js           # 前端交互逻辑
│       └── backend.js       # 真实算法后端API客户端
├── models/                  # 本地训练模型输出目录
├── scripts/
│   ├── start_backend.bat    # Windows启动后端
│   ├── start_frontend.bat   # Windows启动前端
│   └── start_all.ps1        # Windows一键启动
├── requirements.txt         # 根目录Python依赖入口
└── README.md
```

## 3. Windows快速运行

### 3.1 环境要求

- Windows 10或Windows 11，64位；
- Python 3.10及以上，建议Python 3.12；
- Node.js 20.x；
- 8GB内存及以上；
- 不需要NVIDIA显卡，CPU即可演示。

### 3.2 一键启动

进入源码目录，右键使用PowerShell执行：

```powershell
.\scripts\start_all.ps1
```

如果系统提示禁止执行脚本，可先执行：

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

然后再次运行：

```powershell
.\scripts\start_all.ps1
```

一键脚本会打开两个窗口：

1. 后端窗口：安装Python依赖并启动FastAPI服务；
2. 前端窗口：安装Electron依赖并启动桌面软件。

首次运行需要下载Python包和Electron，耗时取决于网络环境。

### 3.3 分别启动

启动后端：

```bat
.\scripts\start_backend.bat
```

启动前端：

```bat
.\scripts\start_frontend.bat
```

## 4. 手动运行

### 4.1 启动Python后端

在项目根目录执行：

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
python backend/main.py
```

看到以下信息说明后端已启动：

```text
Uvicorn running on http://127.0.0.1:8765
```

健康检查：

```bash
curl http://127.0.0.1:8765/health
```

### 4.2 启动Electron前端

另开一个终端，执行：

```bash
cd frontend
npm install
npm start
```

## 5. 前端真实算法演示流程

1. 启动后端和前端；
2. 打开软件左侧“真实算法”页面；
3. 点击“连接后端”，状态显示“ASRI真实算法后端 v2.0.0”；
4. 建议快速演示参数：
   - 主机数量：45；
   - GAT训练轮数：5；
   - PPO训练回合：4；
   - 最大步数：6；
5. 点击“创建算法会话”；
6. 点击“训练GAT”，等待训练完成；
7. 点击“训练PPO”，等待训练完成；
8. 点击“运行真实收敛”；
9. 在右侧查看ASRI、剩余路径、操作数量和动作序列。

## 6. API接口

### 健康检查

```http
GET /health
```

### 创建算法会话

```http
POST /api/v2/sessions
Content-Type: application/json

{
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
  "local_view_k": 2
}
```

### 启动GAT训练

```http
POST /api/v2/sessions/{session_id}/gat/train
Content-Type: application/json

{
  "epochs": 5,
  "learning_rate": 0.0003
}
```

### 启动PPO训练

```http
POST /api/v2/sessions/{session_id}/ppo/train
Content-Type: application/json

{
  "episodes": 4,
  "learning_rate": 0.0003,
  "gamma": 0.95,
  "gae_lambda": 0.95,
  "clip": 0.2,
  "update_every": 2,
  "ppo_epochs": 2
}
```

### 查询训练任务

```http
GET /api/v2/jobs/{job_id}
```

### 运行PPO收敛推理

```http
POST /api/v2/sessions/{session_id}/converge
Content-Type: application/json

{
  "max_steps": 6
}
```

## 7. 本次验证结果

已在Linux沙箱中完成CPU小规模端到端验证：

- 后端服务启动成功；
- `/health`返回正常；
- 创建45主机仿真攻击图成功；
- 生成229个节点、243条边、85个漏洞、13条攻击路径；
- GAT训练完成，最终MAE约为0.107；
- PPO训练完成；
- PPO收敛推理成功；
- 前端页面可创建会话、启动训练、显示日志、展示动作序列；
- 真实算法页面测试样例中，攻击路径由13条降至7条，ASRI为0.4615。

该结果仅用于验证算法链路可运行，不代表论文最终实验数值。

## 8. 复现边界

- v2.0已使用真实PyTorch GAT和PPO训练流程；
- 数据使用内置仿真数据，未严格复现论文原始数据集；
- 不承诺复现论文中的ASRI=0.846等具体数值；
- 当前GAT为纯PyTorch实现，未使用PyTorch Geometric；
- 当前训练规模面向CPU快速演示，大规模实验需要增加训练轮数、PPO回合、路径规模和训练时间；
- 后续可接入NVD、EPSS、KEV真实数据和NASim环境，进一步开展论文级数值复现。

## 9. 打包Windows前端

如果只打包Electron前端，可在Windows PowerShell中执行：

```powershell
cd frontend
.\scripts\build-windows.ps1
```

打包结果位于：

```text
frontend/dist/
```

注意：绿色版exe只包含Electron前端。真实GAT/PPO训练仍需同时运行Python后端。

## 10. 安全与数据说明

本项目当前仅包含仿真数据，不包含真实政务外网IP、真实单位内网域名、账号、密码、Token、API Key、真实漏洞扫描报告、真实资产清单或内部系统截图。上传GitHub前仍应再次检查源码和本地配置，避免误传敏感信息。

## 11. License

MIT
