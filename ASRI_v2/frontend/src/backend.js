/* ASRI v2真实算法后端接入 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = {
    connected: false,
    sessionId: null,
    sessionDetail: null,
    currentJobId: null,
    pollTimer: null,
    lastLogCount: 0,
    lastResult: null
  };

  function backendUrl() {
    return $('backendUrl').value.trim().replace(/\/$/, '');
  }

  async function api(path, options = {}) {
    const response = await fetch(`${backendUrl()}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options
    });
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    if (!response.ok) {
      const message = data && data.detail ? data.detail : `请求失败：${response.status}`;
      throw new Error(message);
    }
    return data;
  }

  function setBackendStatus(connected, message) {
    state.connected = connected;
    const badge = $('backendStatus');
    badge.className = `backend-badge ${connected ? 'online' : 'offline'}`;
    badge.textContent = message || (connected ? '已连接' : '未连接');
  }

  function appendLog(message) {
    const log = $('backendLog');
    const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    if (log.textContent === '等待后端任务……') log.textContent = '';
    log.textContent += `[${time}] ${message}\n`;
    log.scrollTop = log.scrollHeight;
  }

  function setProgress(percent, text) {
    $('jobProgressBar').style.width = `${Math.max(0, Math.min(100, percent || 0))}%`;
    $('jobStatusText').textContent = text || '暂无训练任务';
  }

  async function checkHealth(showMessage = true) {
    try {
      const result = await api('/health');
      setBackendStatus(true, `${result.name} v${result.version}`);
      if (showMessage) appendLog(`后端连接成功：${result.name} v${result.version}`);
      return true;
    } catch (error) {
      setBackendStatus(false, '连接失败');
      if (showMessage) appendLog(`后端连接失败：${error.message}`);
      return false;
    }
  }

  function sessionPayload() {
    return {
      host_count: Number($('backendHostCount').value),
      seed: Number($('backendSeed').value),
      vuln_density: Number($('backendVulnDensity').value),
      topology: $('backendTopology').value,
      hidden_dim: Number($('backendHiddenDim').value),
      gat_layers: Number($('backendGatLayers').value),
      attention_heads: Number($('backendHeads').value),
      max_path_length: 5,
      max_paths: 3000,
      max_steps: Number($('backendMaxSteps').value),
      local_view_k: 2
    };
  }

  async function createSession() {
    if (!(await checkHealth(false))) {
      appendLog('请先启动后端服务：python backend/main.py');
      return;
    }
    setProgress(5, '正在创建算法会话……');
    const result = await api('/api/v2/sessions', {
      method: 'POST',
      body: JSON.stringify(sessionPayload())
    });
    state.sessionId = result.session_id;
    state.sessionDetail = result;
    $('backendSessionInfo').className = 'backend-session';
    $('backendSessionInfo').innerHTML = `
      <div class="session-title">${escapeHtml(result.meta.name)}</div>
      <div class="kv"><span>会话ID</span><strong>${result.session_id}</strong></div>
      <div class="kv"><span>主机资产</span><strong>${result.metrics.asset_count}</strong></div>
      <div class="kv"><span>攻击路径</span><strong>${result.path_count}</strong></div>
      <div class="kv"><span>活跃漏洞</span><strong>${result.metrics.vulnerability_count}</strong></div>
      <div class="kv"><span>KEV漏洞</span><strong>${result.metrics.kev_count}</strong></div>
    `;
    setProgress(10, `会话已创建：${result.session_id}`);
    appendLog(`算法会话创建成功，主机=${result.metrics.asset_count}，路径=${result.path_count}，漏洞=${result.metrics.vulnerability_count}`);
  }

  function requireSession() {
    if (!state.sessionId) {
      appendLog('请先创建真实算法会话。');
      return false;
    }
    return true;
  }

  async function startGatTraining() {
    if (!requireSession()) return;
    const body = {
      epochs: Number($('backendGatEpochs').value),
      learning_rate: Number($('backendGatLr').value)
    };
    const result = await api(`/api/v2/sessions/${state.sessionId}/gat/train`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
    state.currentJobId = result.job_id;
    state.lastLogCount = 0;
    setProgress(12, `GAT训练任务已启动：${result.job_id}`);
    appendLog(`GAT训练任务启动，epochs=${body.epochs}`);
    startPolling();
  }

  async function startPpoTraining() {
    if (!requireSession()) return;
    const body = {
      episodes: Number($('backendPpoEpisodes').value),
      learning_rate: Number($('backendPpoLr').value),
      gamma: Number($('backendGamma').value),
      gae_lambda: 0.95,
      clip: Number($('backendPpoClip').value),
      update_every: 4,
      ppo_epochs: 4
    };
    const result = await api(`/api/v2/sessions/${state.sessionId}/ppo/train`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
    state.currentJobId = result.job_id;
    state.lastLogCount = 0;
    setProgress(12, `PPO训练任务已启动：${result.job_id}`);
    appendLog(`PPO训练任务启动，episodes=${body.episodes}`);
    startPolling();
  }

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollCurrentJob, 1000);
    pollCurrentJob();
  }

  async function pollCurrentJob() {
    if (!state.currentJobId) return;
    try {
      const job = await api(`/api/v2/jobs/${state.currentJobId}`);
      setProgress(job.progress || 0, `${job.type.toUpperCase()}任务：${job.status}（${job.progress || 0}%）`);
      const latest = job.logs.slice(state.lastLogCount);
      state.lastLogCount = job.logs.length;
      latest.forEach((last) => {
        if (last.type === 'progress') appendLog(`GAT epoch ${last.epoch}/${last.epochs}，loss=${last.loss}，MAE=${last.mae}`);
        if (last.type === 'episode') appendLog(`PPO episode ${last.episode}，ASRI=${last.asri}，奖励=${last.total_reward}，操作=${last.operations}`);
        if (last.type === 'update') appendLog(`PPO update ${last.update}，policy_loss=${last.policy_loss}，value_loss=${last.value_loss}`);
      });
      if (job.status === 'completed') {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        state.lastResult = job.result;
        setProgress(100, `${job.type.toUpperCase()}训练完成`);
        appendLog(`${job.type.toUpperCase()}训练完成：${JSON.stringify(job.result)}`);
        renderBackendResult();
      } else if (job.status === 'failed') {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        appendLog(`${job.type.toUpperCase()}训练失败：${job.error}`);
      }
    } catch (error) {
      appendLog(`查询训练任务失败：${error.message}`);
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function runConvergence() {
    if (!requireSession()) return;
    setProgress(80, '正在运行PPO收敛推理……');
    const result = await api(`/api/v2/sessions/${state.sessionId}/converge`, {
      method: 'POST',
      body: JSON.stringify({ max_steps: Number($('backendMaxSteps').value) })
    });
    state.lastResult = { convergence: result.summary };
    setProgress(100, '真实算法收敛完成');
    appendLog(`PPO收敛完成，ASRI=${result.summary.asri}，操作数=${result.summary.operations}`);
    renderBackendResult();
  }

  function renderBackendResult() {
    const box = $('backendResult');
    const result = state.lastResult;
    if (!result) return;
    box.className = 'backend-result';
    let html = '';
    if (result.final_mae !== undefined) {
      html += `<div class="result-block"><h4>GAT训练结果</h4><div class="kv"><span>训练轮数</span><strong>${result.epochs}</strong></div><div class="kv"><span>最终MAE</span><strong>${result.final_mae}</strong></div></div>`;
    }
    if (result.best_asri !== undefined) {
      html += `<div class="result-block"><h4>PPO训练结果</h4><div class="kv"><span>训练回合</span><strong>${result.episodes}</strong></div><div class="kv"><span>最佳ASRI</span><strong>${result.best_asri}</strong></div><div class="kv"><span>最佳总奖励</span><strong>${result.best_total_reward}</strong></div><div class="kv"><span>策略损失</span><strong>${result.last_policy_loss}</strong></div><div class="kv"><span>价值损失</span><strong>${result.last_value_loss}</strong></div></div>`;
    }
    if (result.convergence) {
      const summary = result.convergence;
      html += `<div class="result-block"><h4>PPO收敛推理</h4><div class="kv"><span>ASRI</span><strong>${summary.asri}</strong></div><div class="kv"><span>初始路径</span><strong>${summary.initial_paths}</strong></div><div class="kv"><span>剩余路径</span><strong>${summary.final_paths}</strong></div><div class="kv"><span>操作数量</span><strong>${summary.operations}</strong></div></div>`;
      html += `<div class="result-block"><h4>动作序列</h4>${summary.actions.map((item) => `
        <div class="backend-action">
          <strong>${item.step}. ${escapeHtml(actionLabel(item.type))}</strong>
          <span>${escapeHtml(item.label)}</span>
          <em>奖励 ${item.reward} ｜ 剩余路径 ${item.remaining_paths} ｜ ASRI ${item.asri}</em>
        </div>`).join('')}</div>`;
    }
    box.innerHTML = html;
  }

  function actionLabel(type) {
    return { patch: '补丁部署', segment: '网络分段', acl: '访问控制收紧' }[type] || type;
  }

  function escapeHtml(text) {
    return String(text === undefined ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function bind() {
    $('btnBackendHealth').addEventListener('click', async () => {
      try { await checkHealth(true); } catch (_) { /* 已在日志中显示 */ }
    });
    $('btnCreateBackendSession').addEventListener('click', async () => {
      try { await createSession(); } catch (error) { appendLog(`创建会话失败：${error.message}`); }
    });
    $('btnTrainGat').addEventListener('click', async () => {
      try { await startGatTraining(); } catch (error) { appendLog(`启动GAT训练失败：${error.message}`); }
    });
    $('btnTrainPpo').addEventListener('click', async () => {
      try { await startPpoTraining(); } catch (error) { appendLog(`启动PPO训练失败：${error.message}`); }
    });
    $('btnRunBackendConverge').addEventListener('click', async () => {
      try { await runConvergence(); } catch (error) { appendLog(`运行真实收敛失败：${error.message}`); }
    });
    checkHealth(false);
  }

  document.addEventListener('DOMContentLoaded', bind);
})();
