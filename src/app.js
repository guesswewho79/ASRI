/* 前端交互逻辑 */
(function () {
  'use strict';

  const Engine = window.AttackSurfaceEngine;
  const $ = (id) => document.getElementById(id);

  const state = {
    config: Object.assign({}, Engine.DEFAULT_CONFIG),
    graph: null,
    analysis: null,
    strategyResult: null,
    experiment: null,
    sensitivity: null,
    replayIndex: 0,
    replayTimer: null,
    selectedNodeId: null,
    graphView: {
      scale: 1,
      offsetX: 0,
      offsetY: 0,
      dragging: false,
      lastX: 0,
      lastY: 0
    }
  };

  const pageTitles = {
    dashboard: ['运行总览', '攻击面感知、风险预测、策略收敛与实验评估'],
    graph: ['攻击图分析', '查看异构攻击图、关键路径和高风险节点'],
    decision: ['收敛决策', '生成并回放攻击面收敛动作序列'],
    experiments: ['实验评估', '对比基线方法并分析关键参数敏感性'],
    settings: ['数据与参数', '配置仿真网络、模型参数和数据导入'],
    help: ['使用说明', '了解功能边界、复现范围和后续扩展方式']
  };

  function init() {
    bindNavigation();
    bindActions();
    bindGraphEvents();
    applyConfigToForm();
    generateDemoNetwork(false);
    loadAppInfo();
  }

  function bindNavigation() {
    document.querySelectorAll('.nav-item').forEach((button) => {
      button.addEventListener('click', () => showPage(button.dataset.page));
    });
    $('btnOpenHelp').addEventListener('click', () => showPage('help'));
  }

  function bindActions() {
    $('btnQuickStart').addEventListener('click', () => generateDemoNetwork(true));
    $('btnGenerate').addEventListener('click', () => generateDemoNetwork(true));
    $('btnRefreshAnalysis').addEventListener('click', () => refreshAnalysis(true));
    $('btnApplyConfig').addEventListener('click', () => {
      state.config = readConfigFromForm();
      refreshAnalysis(true);
      showToast('模型与策略参数已应用。', 'success');
    });
    $('btnResetConfig').addEventListener('click', () => {
      state.config = Object.assign({}, Engine.DEFAULT_CONFIG);
      applyConfigToForm();
      refreshAnalysis(true);
      showToast('已恢复默认参数。', 'success');
    });
    $('btnImport').addEventListener('click', importJsonData);
    $('btnImportTop').addEventListener('click', importJsonData);
    $('btnSampleSchema').addEventListener('click', showSampleSchema);
    $('btnGraphRefresh').addEventListener('click', renderGraph);
    $('btnFitGraph').addEventListener('click', () => {
      state.graphView.scale = 1;
      state.graphView.offsetX = 0;
      state.graphView.offsetY = 0;
      renderGraph();
    });
    $('riskFilter').addEventListener('change', renderGraph);
    $('graphMode').addEventListener('change', renderGraph);
    $('nodeSearch').addEventListener('input', renderGraph);

    $('btnRunFullTop').addEventListener('click', runFullStrategy);
    $('btnRunStrategy').addEventListener('click', runFullStrategy);
    $('btnStepReplay').addEventListener('click', stepReplay);
    $('btnAutoReplay').addEventListener('click', toggleAutoReplay);
    $('btnResetReplay').addEventListener('click', resetReplay);

    $('btnRunExperiment').addEventListener('click', runExperiment);
    $('btnRunSensitivity').addEventListener('click', runSensitivity);
    $('btnExportJson').addEventListener('click', exportJson);
    $('btnExportCsv').addEventListener('click', exportCsv);
    $('btnExportReport').addEventListener('click', exportReport);
  }

  async function loadAppInfo() {
    try {
      if (window.desktopApi && window.desktopApi.getAppInfo) {
        const info = await window.desktopApi.getAppInfo();
        document.title = `${info.name} v${info.version}`;
      }
    } catch (_) {
      // 浏览器调试模式下忽略
    }
  }

  function showPage(page) {
    document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === page));
    document.querySelectorAll('.page').forEach((section) => section.classList.toggle('active', section.id === `page-${page}`));
    const title = pageTitles[page] || pageTitles.dashboard;
    $('pageTitle').textContent = title[0];
    $('pageSubtitle').textContent = title[1];
    if (page === 'graph') setTimeout(renderGraph, 30);
    if (page === 'decision') setTimeout(drawAsriCurve, 30);
  }

  function readConfigFromForm() {
    return Engine.normalizeConfig({
      hostCount: Number($('cfgHostCount').value),
      seed: Number($('cfgSeed').value),
      topology: $('cfgTopology').value,
      vulnDensity: Number($('cfgVulnDensity').value),
      maxPathLength: Number($('cfgMaxPathLength').value),
      maxPaths: Number($('cfgMaxPaths').value),
      localViewK: Number($('cfgLocalViewK').value),
      gatLayers: Number($('cfgGatLayers').value),
      attentionHeads: Number($('cfgHeads').value),
      featureDim: Number($('cfgFeatureDim').value),
      ppoClip: Number($('cfgPpoClip').value),
      maxSteps: Number($('cfgMaxSteps').value),
      lambdaCvss: Number($('cfgLambdaCvss').value),
      lambdaThreat: Number($('cfgLambdaThreat').value),
      lambdaBusiness: Number($('cfgLambdaBusiness').value),
      lambdaDefense: Number($('cfgLambdaDefense').value)
    });
  }

  function applyConfigToForm() {
    const cfg = state.config;
    $('cfgHostCount').value = cfg.hostCount;
    $('cfgSeed').value = cfg.seed;
    $('cfgTopology').value = cfg.topology;
    $('cfgVulnDensity').value = cfg.vulnDensity;
    $('cfgMaxPathLength').value = cfg.maxPathLength;
    $('cfgMaxPaths').value = cfg.maxPaths;
    $('cfgLocalViewK').value = cfg.localViewK;
    $('cfgGatLayers').value = cfg.gatLayers;
    $('cfgHeads').value = cfg.attentionHeads;
    $('cfgFeatureDim').value = cfg.featureDim;
    $('cfgPpoClip').value = cfg.ppoClip;
    $('cfgMaxSteps').value = cfg.maxSteps;
    $('cfgLambdaCvss').value = cfg.lambdaCvss;
    $('cfgLambdaThreat').value = cfg.lambdaThreat;
    $('cfgLambdaBusiness').value = cfg.lambdaBusiness;
    $('cfgLambdaDefense').value = cfg.lambdaDefense;
  }

  function generateDemoNetwork(notify) {
    state.config = readConfigFromForm();
    state.graph = Engine.generateNetwork(state.config);
    state.selectedNodeId = null;
    state.strategyResult = null;
    state.experiment = null;
    state.sensitivity = null;
    state.replayIndex = 0;
    refreshAnalysis(false);
    if (notify) showToast(`已生成 ${state.config.hostCount} 主机规模的演示网络。`, 'success');
  }

  function refreshAnalysis(notify) {
    if (!state.graph) return;
    state.analysis = Engine.analyzeGraph(state.graph, state.config);
    renderAll();
    if (notify) showToast('攻击图分析已刷新。', 'success');
  }

  function renderAll() {
    renderSidebar();
    renderDashboard();
    renderTopPaths();
    renderGraph();
    renderDecision();
    renderExperiment();
  }

  function renderSidebar() {
    if (!state.graph || !state.analysis) return;
    $('sidebarDataset').textContent = state.graph.meta.name || '未命名数据集';
    $('sidebarStats').innerHTML = [
      `${state.analysis.metrics.assetCount} 主机`,
      `${state.analysis.metrics.vulnerabilityCount} 活跃漏洞`,
      `${state.analysis.pathCount} 攻击路径`
    ].join('<br>');
  }

  function renderDashboard() {
    if (!state.analysis) return;
    const metrics = state.analysis.metrics;
    $('metricAssets').textContent = formatNumber(metrics.assetCount);
    $('metricPaths').textContent = formatNumber(state.analysis.pathCount);
    $('metricVulns').textContent = formatNumber(metrics.vulnerabilityCount);
    $('metricAsri').textContent = state.strategyResult ? state.strategyResult.summary.asri.toFixed(3) : '0.000';
    renderTopAssets();
    drawRiskChart();
  }

  function renderTopAssets() {
    const tbody = $('topAssetRows');
    const items = state.analysis.topAssets.slice(0, 10);
    tbody.innerHTML = items.map((item) => {
      const risk = item.risk || 0;
      const badge = risk >= 0.65 ? '<span class="badge high">高</span>' : (risk >= 0.45 ? '<span class="badge mid">中</span>' : '<span class="badge low">低</span>');
      return `<tr><td>${escapeHtml(item.label)}</td><td>${item.businessValue}</td><td>${risk.toFixed(3)}</td><td>${badge}</td></tr>`;
    }).join('');
  }

  function drawRiskChart() {
    const canvas = $('riskChart');
    if (!canvas || !state.analysis) return;
    const hosts = state.analysis.graph.nodes.filter((node) => node.type === 'host');
    const buckets = [0, 0, 0, 0, 0];
    hosts.forEach((host) => {
      const idx = Math.min(4, Math.floor((host.risk || 0) * 5));
      buckets[idx] += 1;
    });
    drawBarChart(canvas, buckets.map((count, index) => ({
      label: ['0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1'][index],
      value: count,
      color: ['#22c55e', '#84cc16', '#f59e0b', '#f97316', '#dc2626'][index]
    })), '资产数量');
  }

  function renderTopPaths() {
    const box = $('topPaths');
    if (!state.analysis || !state.analysis.topPaths.length) {
      box.innerHTML = '暂无攻击路径';
      box.className = 'path-list empty-state';
      return;
    }
    box.className = 'path-list';
    box.innerHTML = state.analysis.topPaths.slice(0, 12).map((path, index) => `
      <div class="path-item">
        <strong><em>路径 ${index + 1}</em><span>${path.score.toFixed(3)}</span></strong>
        <p>${path.labels.map(escapeHtml).join(' → ')}</p>
      </div>
    `).join('');
  }

  function bindGraphEvents() {
    const canvas = $('graphCanvas');
    canvas.addEventListener('mousedown', (event) => {
      state.graphView.dragging = true;
      state.graphView.lastX = event.clientX;
      state.graphView.lastY = event.clientY;
      canvas.classList.add('dragging');
    });
    window.addEventListener('mouseup', () => {
      state.graphView.dragging = false;
      canvas.classList.remove('dragging');
    });
    window.addEventListener('mousemove', (event) => {
      if (!state.graphView.dragging) return;
      const dx = event.clientX - state.graphView.lastX;
      const dy = event.clientY - state.graphView.lastY;
      state.graphView.offsetX += dx;
      state.graphView.offsetY += dy;
      state.graphView.lastX = event.clientX;
      state.graphView.lastY = event.clientY;
      renderGraph();
    });
    canvas.addEventListener('wheel', (event) => {
      event.preventDefault();
      const delta = event.deltaY > 0 ? 0.9 : 1.1;
      state.graphView.scale = clamp(state.graphView.scale * delta, 0.35, 3.2);
      renderGraph();
    }, { passive: false });
    canvas.addEventListener('click', (event) => {
      const nearest = findNodeAt(event.offsetX, event.offsetY);
      if (nearest) {
        state.selectedNodeId = nearest.id;
        renderNodeDetails(nearest);
        renderGraph();
      }
    });
  }

  function graphTransform() {
    const canvas = $('graphCanvas');
    const base = Math.min(canvas.width / 1280, canvas.height / 860);
    const scale = base * state.graphView.scale;
    const offsetX = (canvas.width - 1280 * base) / 2 + state.graphView.offsetX;
    const offsetY = (canvas.height - 860 * base) / 2 + state.graphView.offsetY;
    return { scale, offsetX, offsetY };
  }

  function projectNode(node, transform) {
    return {
      x: node.x * transform.scale + transform.offsetX,
      y: node.y * transform.scale + transform.offsetY
    };
  }

  function getVisibleGraph() {
    const mode = $('graphMode').value;
    const filter = $('riskFilter').value;
    const query = $('nodeSearch').value.trim().toLowerCase();
    const nodeSet = new Set();
    const nodes = [];

    state.analysis.graph.nodes.forEach((node) => {
      if (mode === 'host' && node.type !== 'host') return;
      if (filter === 'high' && (node.risk || 0) < 0.58 && node.type !== 'vulnerability') return;
      if (filter === 'high' && node.type === 'vulnerability' && (node.cvss || 0) < 7) return;
      if (filter === 'entry' && !node.isEntry && !node.isTarget && node.type === 'host') return;
      if (filter === 'entry' && node.type !== 'host') return;
      if (query && !`${node.label} ${node.id} ${node.cve || ''}`.toLowerCase().includes(query)) return;
      nodeSet.add(node.id);
      nodes.push(node);
    });

    const edges = state.analysis.graph.edges.filter((edge) => nodeSet.has(edge.source) && nodeSet.has(edge.target));
    return { nodes, edges, nodeSet };
  }

  function renderGraph() {
    if (!state.analysis) return;
    const canvas = $('graphCanvas');
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    drawGrid(ctx, canvas.width, canvas.height);

    const visible = getVisibleGraph();
    const transform = graphTransform();
    const nodeMap = new Map(visible.nodes.map((node) => [node.id, node]));
    const topPath = state.analysis.topPaths[0] ? new Set() : null;
    if (topPath && state.analysis.topPaths[0]) {
      const nodes = state.analysis.topPaths[0].nodes;
      for (let i = 0; i < nodes.length - 1; i += 1) topPath.add(`${nodes[i]}->${nodes[i + 1]}`);
    }

    visible.edges.forEach((edge) => {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) return;
      const p1 = projectNode(source, transform);
      const p2 = projectNode(target, transform);
      const key = `${edge.source}->${edge.target}`;
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      if (topPath && topPath.has(key)) {
        ctx.strokeStyle = '#f97316';
        ctx.lineWidth = 3.2;
      } else {
        ctx.strokeStyle = edge.disabled ? '#cbd5e1' : edgeColor(edge.type);
        ctx.lineWidth = edge.type === 'DEPENDS_ON' ? 1.35 : 0.85;
      }
      if (edge.disabled) ctx.setLineDash([5, 5]); else ctx.setLineDash([]);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    visible.nodes.forEach((node) => drawNode(ctx, node, transform, node.id === state.selectedNodeId));
    drawGraphSummary(ctx, visible);
    if (state.selectedNodeId) {
      const selected = state.analysis.graph.nodes.find((node) => node.id === state.selectedNodeId);
      if (selected) renderNodeDetails(selected);
    }
  }

  function drawGrid(ctx, width, height) {
    ctx.save();
    ctx.strokeStyle = '#e8eef6';
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 40) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    ctx.restore();
  }

  function edgeColor(type) {
    return {
      DEPENDS_ON: '#94a3b8',
      HAS_SERVICE: '#86efac',
      HAS_VULN: '#fca5a5',
      HAS_ACCESS: '#c4b5fd'
    }[type] || '#cbd5e1';
  }

  function nodeColor(node) {
    if (node.patched || node.disabled) return '#94a3b8';
    return {
      host: '#2563eb',
      service: '#0f9f6e',
      vulnerability: '#dc2626',
      account: '#7c3aed'
    }[node.type] || '#64748b';
  }

  function drawNode(ctx, node, transform, selected) {
    const p = projectNode(node, transform);
    const baseRadius = { host: 8, service: 6, vulnerability: 5.5, account: 5.5 }[node.type] || 5;
    const riskBoost = node.type === 'host' ? (node.risk || 0) * 6 : ((node.cvss || 0) / 10) * 3;
    const radius = Math.max(3.5, (baseRadius + riskBoost) * transform.scale * 1.25);

    ctx.beginPath();
    ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = nodeColor(node);
    ctx.fill();
    if (node.isEntry || node.isTarget) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, radius + 4, 0, Math.PI * 2);
      ctx.strokeStyle = node.isEntry ? '#f59e0b' : '#ef4444';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    if (selected) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, radius + 8, 0, Math.PI * 2);
      ctx.strokeStyle = '#0f172a';
      ctx.lineWidth = 2.5;
      ctx.stroke();
    }

    const shouldLabel = selected || node.type === 'host' && ((node.risk || 0) > 0.62 || node.isEntry || node.isTarget);
    if (shouldLabel && transform.scale > 0.32) {
      ctx.font = '12px Microsoft YaHei, sans-serif';
      ctx.fillStyle = '#334155';
      ctx.fillText(truncate(node.label, 16), p.x + radius + 5, p.y + 4);
    }
  }

  function drawGraphSummary(ctx, visible) {
    ctx.save();
    ctx.fillStyle = 'rgba(255,255,255,0.92)';
    ctx.strokeStyle = '#dbe4f0';
    roundRect(ctx, 14, 14, 250, 76, 12);
    ctx.fill(); ctx.stroke();
    ctx.fillStyle = '#172033';
    ctx.font = 'bold 14px Microsoft YaHei, sans-serif';
    ctx.fillText('攻击图视图', 28, 38);
    ctx.font = '12px Microsoft YaHei, sans-serif';
    ctx.fillStyle = '#64748b';
    ctx.fillText(`节点 ${visible.nodes.length} / 边 ${visible.edges.length}`, 28, 60);
    ctx.fillText(`滚轮缩放，拖拽平移，点击查看详情`, 28, 78);
    ctx.restore();
  }

  function findNodeAt(x, y) {
    if (!state.analysis) return null;
    const transform = graphTransform();
    const visible = getVisibleGraph();
    let best = null;
    let bestDist = Infinity;
    visible.nodes.forEach((node) => {
      const p = projectNode(node, transform);
      const dist = Math.hypot(p.x - x, p.y - y);
      if (dist < Math.max(14, 10 * transform.scale) && dist < bestDist) {
        best = node;
        bestDist = dist;
      }
    });
    return best;
  }

  function renderNodeDetails(node) {
    const rows = [];
    rows.push(['名称', node.label]);
    rows.push(['类型', typeLabel(node.type)]);
    rows.push(['风险评分', (node.risk || 0).toFixed(4)]);
    if (node.type === 'host') {
      rows.push(['操作系统', node.os || '—']);
      rows.push(['业务重要性', node.businessValue || '—']);
      rows.push(['节点角色', node.isEntry ? '入口资产' : (node.isTarget ? '核心目标' : '中间资产')]);
      rows.push(['访问控制', node.acl ? `已收紧（${node.aclLevel || 1}级）` : '未收紧']);
    }
    if (node.type === 'service') {
      rows.push(['端口/协议', `${node.port || '—'} / ${node.protocol || '—'}`]);
      rows.push(['是否暴露', node.exposed ? '是' : '否']);
    }
    if (node.type === 'vulnerability') {
      rows.push(['漏洞编号', node.cve || node.label]);
      rows.push(['CVSS', node.cvss]);
      rows.push(['EPSS', node.epss]);
      rows.push(['KEV', node.kev ? '是' : '否']);
      rows.push(['修复状态', node.patched ? '已修复' : '未修复']);
    }
    if (node.type === 'account') rows.push(['权限', node.privilege || '—']);
    $('nodeDetails').className = 'node-details';
    $('nodeDetails').innerHTML = rows.map(([key, value]) => `
      <div class="kv"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>
    `).join('');
  }

  function typeLabel(type) {
    return { host: '主机资产', service: '服务', vulnerability: '漏洞', account: '账户' }[type] || type;
  }

  function runFullStrategy() {
    if (!state.graph) {
      showToast('请先生成或导入攻击图数据。', 'error');
      return;
    }
    setBusy(true, '正在运行收敛策略……');
    setTimeout(() => {
      try {
        state.config = readConfigFromForm();
        state.strategyResult = Engine.runStrategy(state.graph, state.config, 'full');
        state.replayIndex = state.strategyResult.actions.length;
        renderDecision();
        renderDashboard();
        showPage('decision');
        showToast(`收敛完成：ASRI=${state.strategyResult.summary.asri}，操作数=${state.strategyResult.summary.operations}。`, 'success');
      } catch (error) {
        showToast(`收敛运行失败：${error.message}`, 'error');
      } finally {
        setBusy(false);
      }
    }, 60);
  }

  function renderDecision() {
    const result = state.strategyResult;
    if (!result) {
      $('decisionRemaining').textContent = state.analysis ? state.analysis.pathCount : '—';
      $('decisionAsri').textContent = '0.000';
      $('decisionOps').textContent = '0';
      $('decisionDefense').textContent = '0.000';
      $('actionTimeline').innerHTML = '尚未运行收敛策略';
      $('actionTimeline').className = 'timeline empty-state';
      drawAsriCurve();
      return;
    }
    const current = result.curve[Math.min(state.replayIndex, result.curve.length - 1)] || result.curve[0];
    $('decisionRemaining').textContent = formatNumber(current.pathCount);
    $('decisionAsri').textContent = Number(current.asri || 0).toFixed(3);
    $('decisionOps').textContent = Math.min(state.replayIndex, result.actions.length);
    $('decisionDefense').textContent = result.summary.defenseEffectiveness.toFixed(3);
    renderTimeline(result);
    drawAsriCurve();
  }

  function renderTimeline(result) {
    const box = $('actionTimeline');
    box.className = 'timeline';
    box.innerHTML = result.actions.map((action, index) => `
      <div class="timeline-item">
        <div class="timeline-step">${action.step}</div>
        <div class="timeline-card ${index < state.replayIndex ? 'active' : ''}">
          <h4>${escapeHtml(Engine.ACTION_LABEL[action.type] || action.type)}：${escapeHtml(action.label)}</h4>
          <p>${escapeHtml(action.description)}</p>
          <div class="timeline-meta">
            <span>成本 ${action.cost}</span>
            <span>奖励 ${action.reward}</span>
            <span>剩余路径 ${action.remainingPaths}</span>
            <span>ASRI ${action.asri}</span>
          </div>
        </div>
      </div>
    `).join('');
  }

  function stepReplay() {
    if (!state.strategyResult) {
      runFullStrategy();
      return;
    }
    state.replayIndex = Math.min(state.strategyResult.actions.length, state.replayIndex + 1);
    renderDecision();
  }

  function toggleAutoReplay() {
    if (state.replayTimer) {
      clearInterval(state.replayTimer);
      state.replayTimer = null;
      $('btnAutoReplay').textContent = '自动回放';
      return;
    }
    if (!state.strategyResult) {
      runFullStrategy();
      return;
    }
    state.replayIndex = 0;
    renderDecision();
    state.replayTimer = setInterval(() => {
      state.replayIndex += 1;
      if (state.replayIndex >= state.strategyResult.actions.length) {
        clearInterval(state.replayTimer);
        state.replayTimer = null;
        $('btnAutoReplay').textContent = '自动回放';
      }
      renderDecision();
    }, 700);
    $('btnAutoReplay').textContent = '停止回放';
  }

  function resetReplay() {
    if (state.replayTimer) {
      clearInterval(state.replayTimer);
      state.replayTimer = null;
      $('btnAutoReplay').textContent = '自动回放';
    }
    state.replayIndex = 0;
    renderDecision();
  }

  function drawAsriCurve() {
    const canvas = $('asriCurve');
    if (!canvas) return;
    const result = state.strategyResult;
    const points = result ? result.curve.slice(0, Math.max(1, state.replayIndex) + 1) : [{ step: 0, asri: 0 }];
    drawLineChart(canvas, points.map((point) => ({ label: String(point.step), value: point.asri || 0 })), 'ASRI');
  }

  function runExperiment() {
    if (!state.graph) {
      showToast('请先生成或导入攻击图数据。', 'error');
      return;
    }
    setBusy(true, '正在运行基线对比实验……');
    setTimeout(() => {
      try {
        state.config = readConfigFromForm();
        state.experiment = Engine.runExperiment(state.graph, state.config);
        state.strategyResult = state.experiment.full;
        state.replayIndex = state.strategyResult.actions.length;
        renderExperiment();
        renderDecision();
        renderDashboard();
        showToast('基线对比实验已完成。', 'success');
      } catch (error) {
        showToast(`实验失败：${error.message}`, 'error');
      } finally {
        setBusy(false);
      }
    }, 60);
  }

  function runSensitivity() {
    if (!state.graph) {
      showToast('请先生成或导入攻击图数据。', 'error');
      return;
    }
    setBusy(true, '正在运行参数敏感性分析……');
    setTimeout(() => {
      try {
        state.config = readConfigFromForm();
        state.sensitivity = Engine.runSensitivity(state.graph, state.config);
        renderSensitivity();
        showToast('敏感性分析已完成。', 'success');
      } catch (error) {
        showToast(`敏感性分析失败：${error.message}`, 'error');
      } finally {
        setBusy(false);
      }
    }, 60);
  }

  function renderExperiment() {
    if (!state.experiment) {
      drawBarChart($('baselineChart'), [], 'ASRI');
      return;
    }
    $('experimentRows').innerHTML = state.experiment.comparison.map((item) => `
      <tr>
        <td>${escapeHtml(item.method)}</td>
        <td>${item.asri}</td>
        <td>${item.operations}</td>
        <td>${item.convergenceSteps}</td>
        <td>${item.defenseEffectiveness}</td>
      </tr>
    `).join('');
    drawBarChart($('baselineChart'), state.experiment.comparison.map((item, index) => ({
      label: item.method.replace('（', '\n（'),
      value: item.asri,
      color: ['#64748b', '#0f9f6e', '#2563eb'][index] || '#2563eb'
    })), 'ASRI');
  }

  function renderSensitivity() {
    if (!state.sensitivity) return;
    drawBarChart($('lambdaChart'), state.sensitivity.lambda.map((item) => ({ label: item.label, value: item.asri, color: '#2563eb' })), 'ASRI');
    drawBarChart($('kChart'), state.sensitivity.localViewK.map((item) => ({ label: item.label, value: item.asri, color: '#0f9f6e' })), 'ASRI');
    drawBarChart($('layerChart'), state.sensitivity.gatLayers.map((item) => ({ label: item.label, value: item.asri, color: '#7c3aed' })), 'ASRI');
  }

  async function importJsonData() {
    try {
      if (!window.desktopApi || !window.desktopApi.openJsonFile) {
        showToast('当前环境不支持文件导入。', 'error');
        return;
      }
      const result = await window.desktopApi.openJsonFile();
      if (!result) return;
      state.graph = Engine.validateImportedGraph(result.content);
      state.selectedNodeId = null;
      state.strategyResult = null;
      state.experiment = null;
      state.sensitivity = null;
      state.replayIndex = 0;
      refreshAnalysis(false);
      showToast(`已导入：${state.graph.meta.name}`, 'success');
    } catch (error) {
      showToast(`导入失败：${error.message}`, 'error');
    }
  }

  function showSampleSchema() {
    $('schemaPreview').textContent = JSON.stringify(Engine.sampleSchema(), null, 2);
  }

  async function exportJson() {
    if (!state.experiment) {
      showToast('请先运行基线对比实验。', 'error');
      return;
    }
    await saveTextFile('攻击面收敛实验结果.json', Engine.toResultJson(state.experiment), [{ name: 'JSON文件', extensions: ['json'] }]);
  }

  async function exportCsv() {
    if (!state.strategyResult) {
      showToast('请先运行收敛策略。', 'error');
      return;
    }
    await saveTextFile('攻击面收敛动作序列.csv', Engine.toActionCsv(state.strategyResult.actions), [{ name: 'CSV文件', extensions: ['csv'] }]);
  }

  async function exportReport() {
    if (!state.experiment) {
      showToast('请先运行基线对比实验。', 'error');
      return;
    }
    await saveTextFile('攻击面智能预测与收敛实验报告.html', Engine.buildReportHtml(state.experiment), [{ name: 'HTML报告', extensions: ['html'] }]);
  }

  async function saveTextFile(defaultFileName, content, filters) {
    try {
      if (!window.desktopApi || !window.desktopApi.saveFile) {
        showToast('当前环境不支持文件导出。', 'error');
        return;
      }
      const path = await window.desktopApi.saveFile({ defaultFileName, content, filters });
      if (path) showToast(`文件已导出：${path}`, 'success');
    } catch (error) {
      showToast(`导出失败：${error.message}`, 'error');
    }
  }

  function drawBarChart(canvas, data, unitLabel) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    const margin = { left: 56, right: 22, top: 28, bottom: 56 };
    const chartW = width - margin.left - margin.right;
    const chartH = height - margin.top - margin.bottom;
    const max = Math.max(1, ...data.map((item) => item.value));

    ctx.strokeStyle = '#dbe4f0';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, margin.top + chartH);
    ctx.lineTo(margin.left + chartW, margin.top + chartH);
    ctx.stroke();

    ctx.font = '12px Microsoft YaHei, sans-serif';
    ctx.fillStyle = '#64748b';
    for (let i = 0; i <= 4; i += 1) {
      const y = margin.top + chartH - (chartH * i / 4);
      const value = max * i / 4;
      ctx.beginPath();
      ctx.moveTo(margin.left, y);
      ctx.lineTo(margin.left + chartW, y);
      ctx.strokeStyle = '#eef2f7';
      ctx.stroke();
      ctx.fillText(formatAxis(value), 10, y + 4);
    }

    if (!data.length) {
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      ctx.fillText('暂无数据', width / 2, height / 2);
      ctx.textAlign = 'left';
      return;
    }

    const gap = 18;
    const barW = Math.max(18, (chartW - gap * (data.length + 1)) / data.length);
    data.forEach((item, index) => {
      const x = margin.left + gap + index * (barW + gap);
      const h = chartH * (item.value / max);
      const y = margin.top + chartH - h;
      ctx.fillStyle = item.color || '#2563eb';
      roundRect(ctx, x, y, barW, h, 6);
      ctx.fill();
      ctx.fillStyle = '#172033';
      ctx.textAlign = 'center';
      ctx.fillText(formatAxis(item.value), x + barW / 2, y - 7);
      ctx.fillStyle = '#64748b';
      wrapCanvasText(ctx, item.label, x + barW / 2, margin.top + chartH + 20, Math.max(42, barW + gap), 14);
      ctx.textAlign = 'left';
    });

    ctx.fillStyle = '#64748b';
    ctx.fillText(unitLabel || '', margin.left, 18);
  }

  function drawLineChart(canvas, data, unitLabel) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);

    const margin = { left: 56, right: 24, top: 30, bottom: 46 };
    const chartW = width - margin.left - margin.right;
    const chartH = height - margin.top - margin.bottom;
    const max = Math.max(1, ...data.map((item) => item.value));

    ctx.strokeStyle = '#dbe4f0';
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, margin.top + chartH);
    ctx.lineTo(margin.left + chartW, margin.top + chartH);
    ctx.stroke();

    ctx.font = '12px Microsoft YaHei, sans-serif';
    ctx.fillStyle = '#64748b';
    for (let i = 0; i <= 4; i += 1) {
      const y = margin.top + chartH - (chartH * i / 4);
      const value = max * i / 4;
      ctx.beginPath();
      ctx.moveTo(margin.left, y);
      ctx.lineTo(margin.left + chartW, y);
      ctx.strokeStyle = '#eef2f7';
      ctx.stroke();
      ctx.fillText(formatAxis(value), 12, y + 4);
    }

    if (data.length <= 1) {
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      ctx.fillText('运行收敛策略后显示ASRI曲线', width / 2, height / 2);
      ctx.textAlign = 'left';
      return;
    }

    const points = data.map((item, index) => ({
      x: margin.left + chartW * index / Math.max(1, data.length - 1),
      y: margin.top + chartH - chartH * (item.value / max),
      item
    }));

    ctx.beginPath();
    points.forEach((point, index) => {
      if (index === 0) ctx.moveTo(point.x, point.y);
      else ctx.lineTo(point.x, point.y);
    });
    ctx.strokeStyle = '#2563eb';
    ctx.lineWidth = 3;
    ctx.stroke();

    points.forEach((point) => {
      ctx.beginPath();
      ctx.arc(point.x, point.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
      ctx.strokeStyle = '#2563eb';
      ctx.lineWidth = 2;
      ctx.stroke();
    });

    ctx.fillStyle = '#64748b';
    ctx.fillText(unitLabel || '', margin.left, 18);
    ctx.fillText('步骤', margin.left + chartW - 20, height - 14);
  }

  function roundRect(ctx, x, y, width, height, radius) {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
  }

  function wrapCanvasText(ctx, text, x, y, maxWidth, lineHeight) {
    const chars = String(text).split('');
    let line = '';
    let lineIndex = 0;
    chars.forEach((char) => {
      const test = line + char;
      if (ctx.measureText(test).width > maxWidth && line) {
        ctx.fillText(line, x, y + lineIndex * lineHeight);
        line = char;
        lineIndex += 1;
      } else {
        line = test;
      }
    });
    if (line) ctx.fillText(line, x, y + lineIndex * lineHeight);
  }

  function setBusy(isBusy, message) {
    const buttons = document.querySelectorAll('button');
    buttons.forEach((button) => { button.disabled = isBusy; });
    if (isBusy) showToast(message || '正在处理……', 'success', 1200);
  }

  let toastTimer = null;
  function showToast(message, type, duration) {
    const toast = $('toast');
    toast.textContent = message;
    toast.className = `toast ${type || ''}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add('hidden'), duration || 3600);
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString('zh-CN');
  }

  function formatAxis(value) {
    if (Math.abs(value) >= 1000) return `${(value / 1000).toFixed(1)}k`;
    if (Math.abs(value) >= 10) return value.toFixed(0);
    return Number(value).toFixed(2).replace(/\.00$/, '');
  }

  function truncate(text, maxLength) {
    const value = String(text || '');
    return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function escapeHtml(text) {
    return String(text === undefined ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
