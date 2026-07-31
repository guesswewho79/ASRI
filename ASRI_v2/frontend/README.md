# ASRI v2.0 Electron前端

本目录是“政务外网攻击面智能预测与收敛系统 v2.0”的Electron前端。完整运行说明请查看项目根目录的 `README.md`。

## 启动方式

在项目根目录启动后端后，进入本目录：

```bash
npm install
npm start
```

前端默认连接：

```text
http://127.0.0.1:8765
```

也可以在软件“真实算法”页面修改后端地址。

## 页面说明

- 运行总览、攻击图分析、收敛决策、实验评估：v1轻量演示引擎；
- 真实算法：连接Python FastAPI后端，训练纯PyTorch GAT与PPO；
- 数据与参数：配置演示网络、模型和策略参数；
- 使用说明：查看当前版本的算法边界和扩展方向。

## Windows打包

```powershell
.\scripts\build-windows.ps1
```

打包结果位于 `dist/`。绿色版exe只包含前端，真实算法训练仍需同时运行Python后端。
