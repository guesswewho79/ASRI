/* 政务外网攻击面智能预测与收敛系统 - 核心引擎
 * 功能原型说明：
 * 1. 数据结构、动作空间、局部视图、奖励函数和ASRI指标按论文流程实现；
 * 2. GAT/PPO部分以轻量演示模式实现：使用关系感知风险传播与策略排序模拟完整训练链路；
 * 3. 该模式用于软件演示、方法验证和二次开发，不承诺与论文实验数值完全一致。
 */
(function (global) {
  'use strict';

  const VERSION = '1.0.0';
  const HOST_TYPES = ['host', 'service', 'vulnerability', 'account'];
  const RELATION_TYPES = ['DEPENDS_ON', 'HAS_SERVICE', 'HAS_VULN', 'HAS_ACCESS'];

  const DEFAULT_CONFIG = {
    hostCount: 180,
    topology: 'hierarchy',
    seed: 20260731,
    vulnDensity: 2.8,
    maxPathLength: 5,
    maxPaths: 6000,
    maxSteps: 28,
    localViewK: 2,
    gatLayers: 2,
    attentionHeads: 8,
    featureDim: 128,
    ppoClip: 0.2,
    gamma: 0.95,
    lambdaCvss: 0.40,
    lambdaThreat: 0.20,
    lambdaBusiness: 0.20,
    lambdaDefense: 0.20,
    kevBoost: 1.0,
    businessWeight: 0.3,
    patchCost: 1.0,
    segmentCost: 1.4,
    aclCost: 0.8
  };

  const RELATION_WEIGHT = {
    DEPENDS_ON: 1.0,
    HAS_SERVICE: 0.42,
    HAS_VULN: 0.82,
    HAS_ACCESS: 0.58
  };

  const ACTION_LABEL = {
    patch: '补丁部署',
    segment: '网络分段',
    acl: '访问控制收紧'
  };

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function round(value, digits = 4) {
    const p = Math.pow(10, digits);
    return Math.round((Number(value) + Number.EPSILON) * p) / p;
  }

  function hashString(input) {
    let h = 2166136261;
    const text = String(input);
    for (let i = 0; i < text.length; i += 1) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function mulberry32(seed) {
    let t = seed >>> 0;
    return function random() {
      t += 0x6D2B79F5;
      let r = t;
      r = Math.imul(r ^ (r >>> 15), r | 1);
      r ^= r + Math.imul(r ^ (r >>> 7), r | 61);
      return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
    };
  }

  function pick(random, items) {
    return items[Math.floor(random() * items.length) % items.length];
  }

  function sampleNormal(random) {
    const u = Math.max(random(), 1e-9);
    const v = Math.max(random(), 1e-9);
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  }

  function normalizeConfig(config) {
    const merged = Object.assign({}, DEFAULT_CONFIG, config || {});
    const sum = merged.lambdaCvss + merged.lambdaThreat + merged.lambdaBusiness + merged.lambdaDefense;
    if (sum > 0) {
      merged.lambdaCvss /= sum;
      merged.lambdaThreat /= sum;
      merged.lambdaBusiness /= sum;
      merged.lambdaDefense /= sum;
    }
    merged.hostCount = Math.max(30, Math.min(2000, Math.floor(merged.hostCount)));
    merged.maxPathLength = Math.max(2, Math.min(7, Math.floor(merged.maxPathLength)));
    merged.maxPaths = Math.max(500, Math.min(30000, Math.floor(merged.maxPaths)));
    merged.maxSteps = Math.max(5, Math.min(80, Math.floor(merged.maxSteps)));
    merged.localViewK = Math.max(1, Math.min(3, Math.floor(merged.localViewK)));
    merged.gatLayers = Math.max(1, Math.min(4, Math.floor(merged.gatLayers)));
    merged.attentionHeads = Math.max(1, Math.min(16, Math.floor(merged.attentionHeads)));
    merged.featureDim = Math.max(32, Math.min(512, Math.floor(merged.featureDim)));
    merged.ppoClip = clamp(Number(merged.ppoClip), 0.05, 0.5);
    merged.gamma = clamp(Number(merged.gamma), 0.8, 0.999);
    merged.kevBoost = clamp(Number(merged.kevBoost), 0, 3);
    merged.businessWeight = clamp(Number(merged.businessWeight), 0, 1);
    return merged;
  }

  function generateNetwork(options) {
    const config = normalizeConfig(options);
    const random = mulberry32(config.seed);
    const nodes = [];
    const edges = [];
    const hostIds = [];
    const entryHostIds = [];
    const targetHostIds = [];

    const osPool = [
      { name: 'Windows Server 2019', weight: 0.24, cpe: 'cpe:2.3:o:microsoft:windows_server_2019' },
      { name: 'Windows Server 2022', weight: 0.18, cpe: 'cpe:2.3:o:microsoft:windows_server_2022' },
      { name: 'CentOS 7', weight: 0.18, cpe: 'cpe:2.3:o:centos:centos:7' },
      { name: 'Ubuntu Server 22.04', weight: 0.16, cpe: 'cpe:2.3:o:canonical:ubuntu_linux:22.04' },
      { name: 'Windows 10', weight: 0.14, cpe: 'cpe:2.3:o:microsoft:windows_10' },
      { name: '统信服务器操作系统', weight: 0.10, cpe: 'cpe:2.3:o:uniontech:server_os' }
    ];

    const servicePool = [
      { name: 'Web政务服务', port: 443, protocol: 'HTTPS' },
      { name: '统一身份认证', port: 8443, protocol: 'HTTPS' },
      { name: '数据交换服务', port: 7001, protocol: 'TCP' },
      { name: '文件共享服务', port: 445, protocol: 'SMB' },
      { name: '数据库服务', port: 1521, protocol: 'TCP' },
      { name: '运维管理服务', port: 22, protocol: 'SSH' },
      { name: '消息中间件', port: 61616, protocol: 'TCP' }
    ];

    const accountPool = ['业务管理员', '运维账号', '审计账号', '服务账号', '只读账号'];
    const resourcePool = ['开放端口', '服务账号', '共享目录', '运维通道'];

    function sampleOs() {
      const r = random();
      let acc = 0;
      for (const item of osPool) {
        acc += item.weight;
        if (r <= acc) return item;
      }
      return osPool[0];
    }

    const n = config.hostCount;
    const entryCount = Math.max(4, Math.round(n * 0.08));
    const coreCount = Math.max(4, Math.round(n * 0.10));

    for (let i = 0; i < n; i += 1) {
      const isEntry = i < entryCount;
      const isTarget = i >= n - coreCount;
      const level = isEntry ? 0 : (isTarget ? 2 : 1);
      const os = sampleOs();
      const businessValue = isTarget
        ? 8 + Math.floor(random() * 3)
        : (isEntry ? 4 + Math.floor(random() * 4) : 3 + Math.floor(random() * 6));
      const id = `H-${String(i + 1).padStart(4, '0')}`;
      const labelPrefix = isEntry ? '边界接入' : (isTarget ? '核心业务' : '部门业务');
      nodes.push({
        id,
        label: `${labelPrefix}-${i + 1}`,
        type: 'host',
        level,
        os: os.name,
        cpe: os.cpe,
        businessValue,
        isEntry,
        isTarget,
        resourceTypes: resourcePool.slice(0, 2 + Math.floor(random() * 3)),
        patched: false,
        acl: false,
        aclLevel: 0,
        risk: 0,
        baseRisk: 0,
        x: 0,
        y: 0
      });
      hostIds.push(id);
      if (isEntry) entryHostIds.push(id);
      if (isTarget) targetHostIds.push(id);
    }

    function addEdge(source, target, type, extra) {
      if (!source || !target || source === target) return;
      const exists = edges.some((edge) => edge.source === source && edge.target === target && edge.type === type);
      if (exists) return;
      edges.push(Object.assign({
        id: `E-${edges.length + 1}`,
        source,
        target,
        type,
        weight: RELATION_WEIGHT[type] || 0.5,
        disabled: false
      }, extra || {}));
    }

    const entryIds = hostIds.slice(0, entryCount);
    const middleIds = hostIds.slice(entryCount, n - coreCount);
    const coreIds = hostIds.slice(n - coreCount);

    middleIds.forEach((hostId, index) => {
      const parent = entryIds[index % entryIds.length];
      addEdge(parent, hostId, 'DEPENDS_ON', { channel: '政务外网路由' });
      if (config.topology !== 'tree' && random() < 0.34) {
        const secondParent = entryIds[Math.floor(random() * entryIds.length)];
        addEdge(secondParent, hostId, 'DEPENDS_ON', { channel: '冗余链路' });
      }
      if (config.topology === 'grid' && index + 1 < middleIds.length && random() < 0.28) {
        addEdge(hostId, middleIds[index + 1], 'DEPENDS_ON', { channel: '横向互联' });
      }
    });

    coreIds.forEach((hostId, index) => {
      const parents = Math.min(middleIds.length, config.topology === 'star' ? 4 : 2);
      for (let p = 0; p < parents; p += 1) {
        const parent = middleIds[(index * 3 + p * 11 + Math.floor(random() * 7)) % middleIds.length];
        addEdge(parent, hostId, 'DEPENDS_ON', { channel: '核心交换' });
      }
      if (config.topology === 'mesh' && index > 0) {
        addEdge(coreIds[index - 1], hostId, 'DEPENDS_ON', { channel: '核心互联' });
      }
    });

    if (config.topology === 'mesh') {
      const extraCount = Math.floor(n * 0.18);
      for (let i = 0; i < extraCount; i += 1) {
        const source = middleIds[Math.floor(random() * middleIds.length)];
        const target = middleIds[Math.floor(random() * middleIds.length)];
        addEdge(source, target, 'DEPENDS_ON', { channel: '横向互联' });
      }
    }

    let vulnCounter = 1;
    hostIds.forEach((hostId, hostIndex) => {
      const host = nodes.find((node) => node.id === hostId);
      const serviceCount = 1 + (random() < 0.22 ? 1 : 0);
      const accountId = `A-${String(hostIndex + 1).padStart(4, '0')}`;
      const accountName = pick(random, accountPool);
      nodes.push({
        id: accountId,
        label: accountName,
        type: 'account',
        hostId,
        privilege: random() < 0.18 ? '高权限' : '普通权限',
        disabled: false,
        risk: 0,
        x: 0,
        y: 0
      });
      addEdge(accountId, hostId, 'HAS_ACCESS', { privilege: accountName });

      for (let s = 0; s < serviceCount; s += 1) {
        const service = pick(random, servicePool);
        const serviceId = `S-${String(hostIndex + 1).padStart(4, '0')}-${s + 1}`;
        nodes.push({
          id: serviceId,
          label: service.name,
          type: 'service',
          hostId,
          port: service.port,
          protocol: service.protocol,
          exposed: host.isEntry || random() < 0.45,
          disabled: false,
          risk: 0,
          x: 0,
          y: 0
        });
        addEdge(hostId, serviceId, 'HAS_SERVICE', { port: service.port, protocol: service.protocol });

        const expectedVulns = config.vulnDensity / serviceCount;
        let vulnCount = Math.floor(expectedVulns);
        if (random() < expectedVulns - vulnCount) vulnCount += 1;
        if (host.isEntry && random() < 0.55) vulnCount += 1;
        if (host.isTarget && random() < 0.25) vulnCount += 1;
        vulnCount = Math.min(6, vulnCount);

        for (let v = 0; v < vulnCount; v += 1) {
          const year = 2022 + Math.floor(random() * 3);
          const cvss = round(clamp(4.2 + sampleNormal(random) * 1.9 + (host.isEntry ? 0.5 : 0), 2.5, 10), 1);
          const epss = round(clamp((cvss / 12) + sampleNormal(random) * 0.16, 0.01, 0.98), 3);
          const kev = cvss >= 8.5 && random() < 0.22;
          const severity = cvss >= 9 ? '严重' : (cvss >= 7 ? '高危' : (cvss >= 4 ? '中危' : '低危'));
          const vulnId = `V-${String(vulnCounter).padStart(5, '0')}`;
          nodes.push({
            id: vulnId,
            label: `SIM-CVE-${year}-${String(1000 + vulnCounter)}`,
            type: 'vulnerability',
            hostId,
            serviceId,
            cve: `SIM-CVE-${year}-${String(1000 + vulnCounter)}`,
            cvss,
            epss,
            kev,
            severity,
            cpe: host.cpe,
            patched: false,
            risk: 0,
            x: 0,
            y: 0
          });
          addEdge(serviceId, vulnId, 'HAS_VULN', { cvss, severity });
          vulnCounter += 1;
        }
      }
    });

    const graph = {
      meta: {
        name: `政务外网${config.hostCount}节点仿真网络`,
        scale: `${config.hostCount}主机`,
        topology: config.topology,
        seed: config.seed,
        generatedAt: new Date().toISOString(),
        description: '参照政务外网分级组网和横向接入特征生成的内置演示数据',
        engineVersion: VERSION,
        relationTypes: RELATION_TYPES.slice(),
        nodeTypes: HOST_TYPES.slice()
      },
      nodes,
      edges,
      hostIds,
      entryHostIds,
      targetHostIds
    };

    return assignLayout(graph);
  }

  function assignLayout(graph) {
    const hosts = graph.nodes.filter((node) => node.type === 'host');
    const levels = new Map();
    hosts.forEach((host) => {
      const level = Number(host.level || 0);
      if (!levels.has(level)) levels.set(level, []);
      levels.get(level).push(host);
    });

    const width = 1280;
    const height = 860;
    const levelKeys = Array.from(levels.keys()).sort((a, b) => a - b);
    const xGap = width / (levelKeys.length + 1);

    levelKeys.forEach((level, levelIndex) => {
      const group = levels.get(level).sort((a, b) => a.id.localeCompare(b.id));
      group.forEach((host, index) => {
        host.x = xGap * (levelIndex + 1);
        host.y = height * (index + 1) / (group.length + 1);
      });
    });

    const hostMap = new Map(hosts.map((host) => [host.id, host]));
    const grouped = new Map();
    graph.nodes.forEach((node) => {
      if (node.type === 'host') return;
      if (!grouped.has(node.hostId)) grouped.set(node.hostId, []);
      grouped.get(node.hostId).push(node);
    });

    grouped.forEach((children, hostId) => {
      const host = hostMap.get(hostId);
      if (!host) return;
      children.sort((a, b) => a.id.localeCompare(b.id));
      children.forEach((node, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(6, children.length) + (node.type === 'vulnerability' ? 0.45 : 0);
        const radius = node.type === 'vulnerability' ? 46 : 34;
        node.x = host.x + Math.cos(angle) * radius + (node.type === 'account' ? -18 : 10);
        node.y = host.y + Math.sin(angle) * radius;
      });
    });

    return graph;
  }

  function cloneGraph(graph) {
    return JSON.parse(JSON.stringify(graph));
  }

  function activeEdges(graph, type) {
    return graph.edges.filter((edge) => !edge.disabled && (!type || edge.type === type));
  }

  function buildIndex(graph) {
    const nodeMap = new Map();
    const outEdges = new Map();
    const inEdges = new Map();
    graph.nodes.forEach((node) => {
      nodeMap.set(node.id, node);
      outEdges.set(node.id, []);
      inEdges.set(node.id, []);
    });
    graph.edges.forEach((edge) => {
      if (edge.disabled) return;
      if (outEdges.has(edge.source)) outEdges.get(edge.source).push(edge);
      if (inEdges.has(edge.target)) inEdges.get(edge.target).push(edge);
    });
    return { nodeMap, outEdges, inEdges };
  }

  function computeRisks(graph, configInput) {
    const config = normalizeConfig(configInput);
    const { nodeMap, outEdges, inEdges } = buildIndex(graph);
    const hostByService = new Map();
    const vulnsByHost = new Map();
    const servicesByHost = new Map();

    graph.nodes.forEach((node) => {
      if (node.type === 'service') {
        hostByService.set(node.id, node.hostId);
        if (!servicesByHost.has(node.hostId)) servicesByHost.set(node.hostId, []);
        servicesByHost.get(node.hostId).push(node);
      }
      if (node.type === 'vulnerability' && !node.patched) {
        const hostId = node.hostId || hostByService.get(node.serviceId);
        if (!hostId) return;
        if (!vulnsByHost.has(hostId)) vulnsByHost.set(hostId, []);
        vulnsByHost.get(hostId).push(node);
      }
    });

    graph.nodes.forEach((node) => {
      if (node.type === 'vulnerability') {
        node.risk = node.patched ? 0 : clamp((node.cvss / 10) * 0.72 + node.epss * 0.22 + (node.kev ? 0.06 : 0), 0, 1);
        node.baseRisk = node.risk;
      } else if (node.type === 'host') {
        const vulns = vulnsByHost.get(node.id) || [];
        const maxCvss = vulns.length ? Math.max(...vulns.map((v) => v.cvss)) / 10 : 0;
        const maxEpss = vulns.length ? Math.max(...vulns.map((v) => v.epss)) : 0;
        const hasKev = vulns.some((v) => v.kev) ? 1 : 0;
        const degree = (outEdges.get(node.id) || []).length + (inEdges.get(node.id) || []).length;
        const exposure = node.isEntry ? 0.14 : 0;
        const aclDiscount = node.acl ? Math.min(0.24, 0.12 * (node.aclLevel || 1)) : 0;
        const base = clamp(
          config.lambdaCvss * maxCvss +
          config.lambdaThreat * clamp(maxEpss * (1 + config.kevBoost * hasKev), 0, 1.5) / 1.5 +
          config.lambdaBusiness * (node.businessValue / 10) +
          0.12 * clamp(degree / 8, 0, 1) +
          exposure -
          aclDiscount,
          0,
          1
        );
        node.baseRisk = base;
        node.risk = base;
      } else if (node.type === 'service') {
        const vulns = graph.nodes.filter((item) => item.type === 'vulnerability' && item.serviceId === node.id && !item.patched);
        node.baseRisk = vulns.length ? Math.max(...vulns.map((v) => v.cvss / 10)) * 0.8 + (node.exposed ? 0.12 : 0) : 0.08;
        node.risk = clamp(node.baseRisk, 0, 1);
      } else if (node.type === 'account') {
        node.baseRisk = node.privilege === '高权限' ? 0.62 : 0.34;
        node.risk = node.baseRisk;
      }
    });

    const layers = Math.max(1, config.gatLayers);
    const propagationStrength = clamp(0.12 + 0.02 * Math.log2(config.attentionHeads + 1), 0.12, 0.22);
    for (let layer = 0; layer < layers; layer += 1) {
      const nextRisk = new Map();
      graph.nodes.forEach((node) => {
        const incoming = inEdges.get(node.id) || [];
        if (!incoming.length) {
          nextRisk.set(node.id, node.risk || 0);
          return;
        }
        let weighted = 0;
        let totalWeight = 0;
        incoming.forEach((edge) => {
          const source = nodeMap.get(edge.source);
          if (!source) return;
          const relWeight = RELATION_WEIGHT[edge.type] || 0.4;
          const attention = relWeight * (0.55 + (source.baseRisk || source.risk || 0) * 0.45);
          weighted += attention * (source.risk || 0);
          totalWeight += attention;
        });
        const propagated = totalWeight > 0 ? weighted / totalWeight : 0;
        const current = node.baseRisk !== undefined ? node.baseRisk : (node.risk || 0);
        nextRisk.set(node.id, clamp(current * (1 - propagationStrength) + propagated * propagationStrength, 0, 1));
      });
      graph.nodes.forEach((node) => {
        node.risk = nextRisk.get(node.id) || 0;
      });
    }

    return graph;
  }

  function enumerateAttackPaths(graph, options) {
    const config = normalizeConfig(options);
    const hosts = graph.nodes.filter((node) => node.type === 'host');
    const hostIds = new Set(hosts.map((node) => node.id));
    const entryIds = graph.entryHostIds && graph.entryHostIds.length
      ? graph.entryHostIds.filter((id) => hostIds.has(id))
      : hosts.filter((node) => node.isEntry).map((node) => node.id);
    const targetIds = graph.targetHostIds && graph.targetHostIds.length
      ? new Set(graph.targetHostIds.filter((id) => hostIds.has(id)))
      : new Set(hosts.filter((node) => node.isTarget).map((node) => node.id));

    const traversableIds = new Set(hosts.filter((node) => !node.neutralized).map((node) => node.id));
    const adjacency = new Map();
    hosts.forEach((host) => adjacency.set(host.id, []));
    activeEdges(graph, 'DEPENDS_ON').forEach((edge) => {
      if (hostIds.has(edge.source) && hostIds.has(edge.target) && traversableIds.has(edge.source) && traversableIds.has(edge.target)) {
        adjacency.get(edge.source).push(edge.target);
      }
    });

    const paths = [];
    const visited = new Set();
    const current = [];

    function dfs(nodeId, depth) {
      if (paths.length >= config.maxPaths || !traversableIds.has(nodeId)) return;
      current.push(nodeId);
      visited.add(nodeId);
      if (targetIds.has(nodeId) && current.length >= 2) {
        paths.push(current.slice());
      }
      if (depth < config.maxPathLength) {
        const neighbors = adjacency.get(nodeId) || [];
        for (const next of neighbors) {
          if (!visited.has(next)) dfs(next, depth + 1);
          if (paths.length >= config.maxPaths) break;
        }
      }
      visited.delete(nodeId);
      current.pop();
    }

    entryIds.forEach((entryId) => dfs(entryId, 1));
    return paths;
  }

  function pathScore(path, nodeMap) {
    if (!path || !path.length) return 0;
    let riskSum = 0;
    let maxBusiness = 0;
    path.forEach((id) => {
      const node = nodeMap.get(id);
      if (!node) return;
      riskSum += node.risk || 0;
      maxBusiness = Math.max(maxBusiness, (node.businessValue || 0) / 10);
    });
    return clamp((riskSum / path.length) * 0.75 + maxBusiness * 0.25, 0, 1);
  }

  function analyzeGraph(graphInput, configInput) {
    const config = normalizeConfig(configInput);
    const graph = computeRisks(graphInput, config);
    const paths = enumerateAttackPaths(graph, config);
    const { nodeMap } = buildIndex(graph);
    const scoredPaths = paths.map((path) => ({
      nodes: path,
      score: pathScore(path, nodeMap),
      labels: path.map((id) => nodeMap.get(id) ? nodeMap.get(id).label : id)
    })).sort((a, b) => b.score - a.score);

    const hostPathCount = new Map();
    const edgePathCount = new Map();
    paths.forEach((path) => {
      path.forEach((id) => hostPathCount.set(id, (hostPathCount.get(id) || 0) + 1));
      for (let i = 0; i < path.length - 1; i += 1) {
        const key = `${path[i]}->${path[i + 1]}`;
        edgePathCount.set(key, (edgePathCount.get(key) || 0) + 1);
      }
    });

    const hosts = graph.nodes.filter((node) => node.type === 'host');
    const activeVulns = graph.nodes.filter((node) => node.type === 'vulnerability' && !node.patched);
    const risks = hosts.map((node) => node.risk || 0).sort((a, b) => b - a);
    const maxCvss = activeVulns.length ? Math.max(...activeVulns.map((node) => node.cvss)) : 0;
    const kevCount = activeVulns.filter((node) => node.kev).length;

    return {
      graph,
      paths: scoredPaths,
      pathCount: paths.length,
      rawPathCount: paths.length,
      hostPathCount,
      edgePathCount,
      metrics: {
        assetCount: hosts.length,
        nodeCount: graph.nodes.length,
        edgeCount: graph.edges.filter((edge) => !edge.disabled).length,
        vulnerabilityCount: activeVulns.length,
        kevCount,
        maxCvss: round(maxCvss, 1),
        maxRisk: round(risks[0] || 0, 4),
        avgRisk: round(risks.reduce((sum, item) => sum + item, 0) / Math.max(1, risks.length), 4),
        highRiskAssets: hosts.filter((node) => (node.risk || 0) >= 0.65).length
      },
      topAssets: hosts.slice().sort((a, b) => (b.risk || 0) - (a.risk || 0)).slice(0, 20),
      topPaths: scoredPaths.slice(0, 30)
    };
  }

  function getKHopHosts(graph, centerId, k) {
    const allowed = new Set([centerId]);
    let frontier = [centerId];
    const hostIds = new Set(graph.nodes.filter((node) => node.type === 'host').map((node) => node.id));
    for (let depth = 0; depth < k; depth += 1) {
      const next = [];
      activeEdges(graph, 'DEPENDS_ON').forEach((edge) => {
        if (frontier.includes(edge.source) && hostIds.has(edge.target) && !allowed.has(edge.target)) {
          allowed.add(edge.target);
          next.push(edge.target);
        }
        if (frontier.includes(edge.target) && hostIds.has(edge.source) && !allowed.has(edge.source)) {
          allowed.add(edge.source);
          next.push(edge.source);
        }
      });
      frontier = next;
    }
    return allowed;
  }

  function buildCandidateActions(graph, analysis, configInput, mode) {
    const config = normalizeConfig(configInput);
    const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]));
    const totalPaths = Math.max(1, analysis.pathCount);
    const criticalHost = analysis.topAssets[0] ? analysis.topAssets[0].id : null;
    const localHosts = mode === 'full' && criticalHost ? getKHopHosts(graph, criticalHost, config.localViewK) : null;

    const candidates = [];
    const vulns = graph.nodes.filter((node) => node.type === 'vulnerability' && !node.patched);
    vulns.forEach((vuln) => {
      const hostId = vuln.hostId || (nodeMap.get(vuln.serviceId) || {}).hostId;
      const host = nodeMap.get(hostId);
      if (!host) return;
      const pathsThrough = analysis.hostPathCount.get(hostId) || 0;
      const activeVulnsOnHost = graph.nodes.filter((node) => node.type === 'vulnerability' && !node.patched && (node.hostId === hostId || node.serviceId && (nodeMap.get(node.serviceId) || {}).hostId === hostId));
      const completesPatch = activeVulnsOnHost.length <= 1;
      const pathRemovalRatio = completesPatch
        ? clamp(pathsThrough / totalPaths, 0, 1)
        : clamp((pathsThrough / totalPaths) * (0.08 / Math.max(1, activeVulnsOnHost.length)), 0, 1);
      const deltaRatio = clamp(pathRemovalRatio * clamp(0.55 + vuln.cvss / 12, 0.55, 1), 0, 1);
      const threat = clamp(vuln.epss * (1 + config.kevBoost * (vuln.kev ? 1 : 0)), 0, 1.6) / 1.6;
      candidates.push({
        id: `ACT-P-${vuln.id}`,
        type: 'patch',
        targetId: vuln.id,
        hostId,
        label: `修复 ${vuln.label}`,
        description: completesPatch ? `在 ${host.label} 上部署补丁，清除最后活跃漏洞并阻断相关路径` : `在 ${host.label} 上部署补丁，消除 ${vuln.severity} 漏洞`,
        cost: config.patchCost,
        cvss: vuln.cvss / 10,
        threat,
        business: host.businessValue / 10,
        deltaRatio,
        pathsThrough,
        completesPatch,
        remainingVulns: activeVulnsOnHost.length,
        relationType: 'HAS_VULN'
      });
    });

    activeEdges(graph, 'DEPENDS_ON').forEach((edge) => {
      const key = `${edge.source}->${edge.target}`;
      const pathsThrough = analysis.edgePathCount.get(key) || 0;
      if (!pathsThrough) return;
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) return;
      const deltaRatio = clamp(pathsThrough / totalPaths, 0, 1);
      candidates.push({
        id: `ACT-S-${edge.id}`,
        type: 'segment',
        targetId: edge.id,
        hostId: edge.target,
        label: `切断 ${source.label} → ${target.label}`,
        description: `在两资产间实施网络分段，阻断${pathsThrough}条候选攻击路径`,
        cost: config.segmentCost,
        cvss: Math.max(source.risk || 0, target.risk || 0),
        threat: Math.max(source.risk || 0, target.risk || 0) * 0.72,
        business: target.businessValue / 10,
        deltaRatio,
        pathsThrough,
        relationType: 'DEPENDS_ON'
      });
    });

    graph.nodes.filter((node) => node.type === 'host' && !node.acl).forEach((host) => {
      const pathsThrough = analysis.hostPathCount.get(host.id) || 0;
      if (!pathsThrough && !host.isEntry) return;
      const deltaRatio = clamp(pathsThrough / totalPaths, 0, 1) * 0.65;
      candidates.push({
        id: `ACT-A-${host.id}`,
        type: 'acl',
        targetId: host.id,
        hostId: host.id,
        label: `收紧 ${host.label} 访问控制`,
        description: `收紧${(host.resourceTypes || []).join('、') || '关键资源'}的访问控制策略`,
        cost: config.aclCost,
        cvss: host.risk || 0,
        threat: (host.risk || 0) * 0.65,
        business: host.businessValue / 10,
        deltaRatio,
        pathsThrough,
        relationType: 'HAS_ACCESS'
      });
    });

    candidates.forEach((candidate, index) => {
      const deterministicNoise = (mulberry32(hashString(candidate.id + config.seed))() - 0.5) * config.ppoClip * 0.08;
      candidate.reward = clamp(
        config.lambdaCvss * candidate.cvss +
        config.lambdaThreat * candidate.threat +
        config.lambdaBusiness * config.businessWeight * candidate.business +
        config.lambdaDefense * candidate.deltaRatio +
        deterministicNoise,
        -1,
        2
      );
      const effectiveDelta = candidate.type === 'segment'
        ? candidate.deltaRatio
        : (candidate.completesPatch ? candidate.deltaRatio : candidate.deltaRatio * 0.05);
      const actionBonus = candidate.type === 'segment' ? 0.10 : (candidate.completesPatch ? 0.14 : -0.12);
      candidate.priority = (candidate.reward * 0.15 + effectiveDelta * 8.0 + actionBonus) / Math.max(0.35, candidate.cost);
      candidate.index = index;
    });

    if (mode === 'static') {
      return candidates
        .filter((item) => item.type === 'patch')
        .sort((a, b) => (b.pathsThrough / Math.max(1, b.remainingVulns)) - (a.pathsThrough / Math.max(1, a.remainingVulns)) || b.cvss - a.cvss)
        .slice(0, 80);
    }
    if (mode === 'greedy') {
      return candidates.sort((a, b) => b.deltaRatio - a.deltaRatio || b.cvss - a.cvss).slice(0, 80);
    }
    const fullCandidates = candidates.filter((item) => item.type === 'segment' || item.completesPatch || item.type === 'acl');
    return fullCandidates.sort((a, b) => b.deltaRatio - a.deltaRatio || b.priority - a.priority).slice(0, 100);
  }

  function applyAction(graph, action) {
    if (!action) return graph;
    if (action.type === 'patch') {
      const vuln = graph.nodes.find((node) => node.id === action.targetId);
      if (vuln) {
        vuln.patched = true;
        vuln.risk = 0;
        const host = graph.nodes.find((node) => node.id === action.hostId);
        if (host) {
          const activeVulns = graph.nodes.filter((node) => node.type === 'vulnerability' && !node.patched && node.hostId === host.id);
          if (!activeVulns.length) host.neutralized = true;
        }
      }
    } else if (action.type === 'segment') {
      const edge = graph.edges.find((item) => item.id === action.targetId);
      if (edge) edge.disabled = true;
    } else if (action.type === 'acl') {
      const host = graph.nodes.find((node) => node.id === action.targetId);
      if (host) {
        host.acl = true;
        host.aclLevel = (host.aclLevel || 0) + 1;
        host.neutralized = true;
      }
    }
    return graph;
  }

  function maxCvssOnAttackPaths(analysis) {
    if (!analysis || !analysis.paths || !analysis.paths.length) return 0;
    const hostMaxCvss = new Map();
    analysis.graph.nodes.forEach((node) => {
      if (node.type !== 'vulnerability' || node.patched) return;
      const hostId = node.hostId;
      if (!hostId) return;
      hostMaxCvss.set(hostId, Math.max(hostMaxCvss.get(hostId) || 0, node.cvss || 0));
    });
    let max = 0;
    analysis.paths.forEach((path) => {
      path.nodes.forEach((hostId) => {
        max = Math.max(max, hostMaxCvss.get(hostId) || 0);
      });
    });
    return max;
  }

  function summarizeRun(initialAnalysis, finalAnalysis, actions, curve, elapsedMs) {
    const initialPaths = Math.max(1, initialAnalysis.pathCount);
    const finalPaths = finalAnalysis.pathCount;
    const asri = clamp(1 - finalPaths / initialPaths, 0, 1);
    const initialMaxCvss = maxCvssOnAttackPaths(initialAnalysis);
    const finalMaxCvss = maxCvssOnAttackPaths(finalAnalysis);
    const defenseEffectiveness = initialMaxCvss > 0 ? clamp(1 - finalMaxCvss / initialMaxCvss, 0, 1) : 0;
    let plateau = curve.length;
    const finalAsri = curve.length ? curve[curve.length - 1].asri : 0;
    for (let i = 0; i < curve.length; i += 1) {
      if (Math.abs((curve[i].asri || 0) - finalAsri) <= 0.01) {
        plateau = Math.max(1, i);
        break;
      }
    }
    return {
      initialPaths,
      finalPaths,
      asri: round(asri, 4),
      operations: actions.length,
      convergenceSteps: plateau,
      defenseEffectiveness: round(defenseEffectiveness, 4),
      inferenceMs: round(elapsedMs, 1),
      totalCost: round(actions.reduce((sum, item) => sum + (item.cost || 0), 0), 2),
      averageReward: round(actions.reduce((sum, item) => sum + (item.reward || 0), 0) / Math.max(1, actions.length), 4)
    };
  }

  function runStrategy(graphInput, configInput, modeInput) {
    const config = normalizeConfig(configInput);
    const mode = modeInput || 'full';
    const startedAt = (global.performance && global.performance.now) ? global.performance.now() : Date.now();
    const graph = cloneGraph(graphInput);
    const initialAnalysis = analyzeGraph(graph, config);
    const actions = [];
    const curve = [{
      step: 0,
      asri: 0,
      pathCount: initialAnalysis.pathCount,
      maxCvss: initialAnalysis.metrics.maxCvss,
      avgRisk: initialAnalysis.metrics.avgRisk
    }];

    let workingAnalysis = initialAnalysis;
    for (let step = 1; step <= config.maxSteps; step += 1) {
      const candidates = buildCandidateActions(graph, workingAnalysis, config, mode);
      if (!candidates.length) break;
      const selected = candidates[0];
      applyAction(graph, selected);
      workingAnalysis = analyzeGraph(graph, config);
      const initialPaths = Math.max(1, initialAnalysis.pathCount);
      const asri = clamp(1 - workingAnalysis.pathCount / initialPaths, 0, 1);
      actions.push(Object.assign({}, selected, {
        step,
        remainingPaths: workingAnalysis.pathCount,
        asri: round(asri, 4),
        reward: round(selected.reward, 4),
        priority: round(selected.priority, 4),
        deltaRatio: round(selected.deltaRatio, 4)
      }));
      curve.push({
        step,
        asri: round(asri, 4),
        pathCount: workingAnalysis.pathCount,
        maxCvss: workingAnalysis.metrics.maxCvss,
        avgRisk: workingAnalysis.metrics.avgRisk,
        actionType: selected.type,
        actionLabel: selected.label
      });
      if (asri >= 0.98) break;
      if (mode !== 'static' && step >= 8) {
        const recent = curve.slice(-4).map((item) => item.asri);
        const max = Math.max(...recent);
        const min = Math.min(...recent);
        if (max - min <= 0.004 && selected.deltaRatio < 0.01) break;
      }
    }

    const endedAt = (global.performance && global.performance.now) ? global.performance.now() : Date.now();
    const summary = summarizeRun(initialAnalysis, workingAnalysis, actions, curve, endedAt - startedAt);
    return {
      mode,
      modeLabel: mode === 'full' ? '完整模型（演示策略）' : (mode === 'greedy' ? '贪心策略' : '静态CVSS优先'),
      graph,
      initialAnalysis,
      finalAnalysis: workingAnalysis,
      actions,
      curve,
      summary,
      config
    };
  }

  function runExperiment(graphInput, configInput) {
    const config = normalizeConfig(configInput);
    const full = runStrategy(graphInput, config, 'full');
    const greedy = runStrategy(graphInput, config, 'greedy');
    const staticRule = runStrategy(graphInput, config, 'static');
    return {
      full,
      greedy,
      staticRule,
      comparison: [
        {
          method: '静态规则（CVSS优先）',
          asri: staticRule.summary.asri,
          operations: staticRule.summary.operations,
          convergenceSteps: staticRule.summary.convergenceSteps,
          defenseEffectiveness: staticRule.summary.defenseEffectiveness,
          inferenceMs: staticRule.summary.inferenceMs
        },
        {
          method: '贪心路径收敛',
          asri: greedy.summary.asri,
          operations: greedy.summary.operations,
          convergenceSteps: greedy.summary.convergenceSteps,
          defenseEffectiveness: greedy.summary.defenseEffectiveness,
          inferenceMs: greedy.summary.inferenceMs
        },
        {
          method: '完整模型（演示策略）',
          asri: full.summary.asri,
          operations: full.summary.operations,
          convergenceSteps: full.summary.convergenceSteps,
          defenseEffectiveness: full.summary.defenseEffectiveness,
          inferenceMs: full.summary.inferenceMs
        }
      ]
    };
  }

  function runSensitivity(graphInput, configInput) {
    const base = normalizeConfig(configInput);
    const lambdaValues = [0.20, 0.30, 0.40, 0.50, 0.60];
    const kValues = [1, 2, 3];
    const layerValues = [1, 2, 3];

    function withLambda(value) {
      const remain = 1 - value;
      return Object.assign({}, base, {
        lambdaCvss: value,
        lambdaThreat: remain / 3,
        lambdaBusiness: remain / 3,
        lambdaDefense: remain / 3,
        maxSteps: Math.min(base.maxSteps, 18)
      });
    }

    const lambda = lambdaValues.map((value) => {
      const result = runStrategy(graphInput, withLambda(value), 'full');
      return { label: `λ=${value.toFixed(1)}`, value, asri: result.summary.asri, operations: result.summary.operations };
    });
    const localViewK = kValues.map((value) => {
      const result = runStrategy(graphInput, Object.assign({}, base, { localViewK: value, maxSteps: Math.min(base.maxSteps, 18) }), 'full');
      return { label: `k=${value}`, value, asri: result.summary.asri, operations: result.summary.operations };
    });
    const gatLayers = layerValues.map((value) => {
      const result = runStrategy(graphInput, Object.assign({}, base, { gatLayers: value, maxSteps: Math.min(base.maxSteps, 18) }), 'full');
      return { label: `L=${value}`, value, asri: result.summary.asri, operations: result.summary.operations };
    });
    return { lambda, localViewK, gatLayers };
  }

  function validateImportedGraph(input) {
    let graph = input;
    if (typeof input === 'string') graph = JSON.parse(input);
    if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
      throw new Error('数据格式不正确：需要包含 nodes 和 edges 数组');
    }
    const normalized = cloneGraph(graph);
    normalized.meta = normalized.meta || {};
    normalized.meta.name = normalized.meta.name || '导入的攻击图数据';
    normalized.meta.importedAt = new Date().toISOString();
    normalized.nodes.forEach((node, index) => {
      node.id = node.id || `N-${index + 1}`;
      node.label = node.label || node.id;
      node.type = HOST_TYPES.includes(node.type) ? node.type : 'host';
      node.risk = Number(node.risk || 0);
      if (node.type === 'host') {
        node.level = Number(node.level === undefined ? 1 : node.level);
        node.businessValue = Number(node.businessValue || 5);
        node.isEntry = Boolean(node.isEntry);
        node.isTarget = Boolean(node.isTarget);
      }
    });
    normalized.edges.forEach((edge, index) => {
      edge.id = edge.id || `E-${index + 1}`;
      edge.type = RELATION_TYPES.includes(edge.type) ? edge.type : 'DEPENDS_ON';
      edge.disabled = Boolean(edge.disabled);
      edge.weight = Number(edge.weight || RELATION_WEIGHT[edge.type] || 0.5);
    });
    normalized.hostIds = normalized.nodes.filter((node) => node.type === 'host').map((node) => node.id);
    if (!normalized.entryHostIds || !normalized.entryHostIds.length) {
      normalized.entryHostIds = normalized.nodes.filter((node) => node.type === 'host' && node.isEntry).map((node) => node.id);
    }
    if (!normalized.targetHostIds || !normalized.targetHostIds.length) {
      normalized.targetHostIds = normalized.nodes.filter((node) => node.type === 'host' && node.isTarget).map((node) => node.id);
    }
    if (!normalized.entryHostIds.length) normalized.entryHostIds = normalized.hostIds.slice(0, Math.max(1, Math.floor(normalized.hostIds.length * 0.08)));
    if (!normalized.targetHostIds.length) normalized.targetHostIds = normalized.hostIds.slice(-Math.max(1, Math.floor(normalized.hostIds.length * 0.08)));
    return assignLayout(normalized);
  }

  function toActionCsv(actions) {
    const header = ['步骤', '动作类型', '动作', '说明', '成本', '奖励', '路径减少估计', '剩余路径', 'ASRI'];
    const rows = actions.map((item) => [
      item.step,
      ACTION_LABEL[item.type] || item.type,
      item.label,
      item.description,
      item.cost,
      item.reward,
      item.deltaRatio,
      item.remainingPaths,
      item.asri
    ]);
    return [header, ...rows].map((row) => row.map((cell) => `"${String(cell === undefined ? '' : cell).replace(/"/g, '""')}"`).join(',')).join('\n');
  }

  function toResultJson(experiment) {
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      engineVersion: VERSION,
      summary: experiment.full.summary,
      comparison: experiment.comparison,
      actions: experiment.full.actions,
      curve: experiment.full.curve,
      config: experiment.full.config
    }, null, 2);
  }

  function buildReportHtml(experiment) {
    const full = experiment.full;
    const rows = experiment.comparison.map((item) => `
      <tr>
        <td>${escapeHtml(item.method)}</td>
        <td>${item.asri}</td>
        <td>${item.operations}</td>
        <td>${item.convergenceSteps}</td>
        <td>${item.defenseEffectiveness}</td>
        <td>${item.inferenceMs}</td>
      </tr>`).join('');
    const actionRows = full.actions.map((item) => `
      <tr>
        <td>${item.step}</td>
        <td>${escapeHtml(ACTION_LABEL[item.type] || item.type)}</td>
        <td>${escapeHtml(item.label)}</td>
        <td>${item.cost}</td>
        <td>${item.reward}</td>
        <td>${item.remainingPaths}</td>
        <td>${item.asri}</td>
      </tr>`).join('');
    return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>攻击面智能预测与收敛实验报告</title>
<style>
body{font-family:"Microsoft YaHei",Arial,sans-serif;margin:36px;color:#172033;line-height:1.65}h1{font-size:24px}h2{font-size:18px;margin-top:28px}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{border:1px solid #dbe3ef;border-radius:10px;padding:14px 18px;min-width:150px}.num{font-size:26px;font-weight:700;color:#1d4ed8}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #dbe3ef;padding:8px;text-align:left}th{background:#f1f5f9}.note{color:#64748b;font-size:13px}</style>
</head>
<body>
<h1>攻击面智能预测与收敛实验报告</h1>
<p class="note">生成时间：${new Date().toLocaleString('zh-CN')}；引擎版本：${VERSION}。本报告由功能原型软件生成。</p>
<div class="cards">
  <div class="card"><div>ASRI</div><div class="num">${full.summary.asri}</div></div>
  <div class="card"><div>操作数量</div><div class="num">${full.summary.operations}</div></div>
  <div class="card"><div>收敛步数</div><div class="num">${full.summary.convergenceSteps}</div></div>
  <div class="card"><div>防御有效性</div><div class="num">${full.summary.defenseEffectiveness}</div></div>
</div>
<h2>一、方法对比</h2>
<table><thead><tr><th>方法</th><th>ASRI</th><th>操作数量</th><th>收敛步数</th><th>防御有效性</th><th>耗时/ms</th></tr></thead><tbody>${rows}</tbody></table>
<h2>二、收敛动作序列</h2>
<table><thead><tr><th>步骤</th><th>类型</th><th>动作</th><th>成本</th><th>奖励</th><th>剩余路径</th><th>ASRI</th></tr></thead><tbody>${actionRows}</tbody></table>
<h2>三、复现边界说明</h2>
<p>本原型实现了论文中的攻击图、局部视图、三类收敛动作、奖励函数和ASRI指标。GAT/PPO部分采用轻量演示策略，适用于功能验证和二次开发，不作为论文精确数值复现结果。</p>
</body></html>`;
  }

  function escapeHtml(text) {
    return String(text === undefined ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function sampleSchema() {
    return {
      description: '导入JSON需包含 nodes 与 edges。节点type可为 host/service/vulnerability/account，边type可为 DEPENDS_ON/HAS_SERVICE/HAS_VULN/HAS_ACCESS。',
      example: {
        meta: { name: '示例攻击图' },
        nodes: [
          { id: 'H-1', label: '边界服务器', type: 'host', level: 0, isEntry: true, businessValue: 6 },
          { id: 'H-2', label: '核心业务系统', type: 'host', level: 2, isTarget: true, businessValue: 10 },
          { id: 'S-1', label: 'Web服务', type: 'service', hostId: 'H-1', port: 443 },
          { id: 'V-1', label: '示例漏洞', type: 'vulnerability', hostId: 'H-1', serviceId: 'S-1', cvss: 9.1, epss: 0.62, kev: true }
        ],
        edges: [
          { source: 'H-1', target: 'H-2', type: 'DEPENDS_ON' },
          { source: 'H-1', target: 'S-1', type: 'HAS_SERVICE' },
          { source: 'S-1', target: 'V-1', type: 'HAS_VULN' }
        ]
      }
    };
  }

  global.AttackSurfaceEngine = {
    VERSION,
    DEFAULT_CONFIG,
    ACTION_LABEL,
    normalizeConfig,
    generateNetwork,
    validateImportedGraph,
    analyzeGraph,
    buildCandidateActions,
    applyAction,
    runStrategy,
    runExperiment,
    runSensitivity,
    toActionCsv,
    toResultJson,
    buildReportHtml,
    sampleSchema,
    cloneGraph
  };
})(window);
