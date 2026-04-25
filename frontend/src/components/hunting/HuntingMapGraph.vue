<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

import * as echarts from "echarts";

export type GraphNode = {
  id: string;
  name: string;
  severity: string | null;
  is_neighbor: boolean;
  detail: {
    asset_id: string | null;
    host: string;
    ip: string;
    ports: string;
    services: string;
    open_finding_types: string;
    highest_severity: string;
    vulnerability_count: number;
  } | null;
};

export type GraphLink = {
  source: string;
  target: string;
  relation: string;
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff0308",
  high: "#f36d14",
  medium: "#ffe240",
  low: "#389e0d",
  info: "#096dd9",
};

// Severity rank for hub highlight (highest connected asset)
const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

// Domain hubs: violet (matches dashed root-domain edges)
// IP hubs: teal (matches solid shared-ip edges)
const HUB_DOMAIN_COLOR = "#7c3aed";
const HUB_IP_COLOR = "#0891b2";

// Returns true if a hub node's name looks like an IPv4 address (optionally with CIDR)
function isIpHub(name: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/.test(name.trim());
}

// Campaign tag colors (outer ring on tagged nodes)
const TAG_COLORS: Record<string, string> = {
  investigating:  "#f59e0b",
  accepted_risk:  "#64748b",
  resolved:       "#22c55e",
};

export type NodeTagMap = Record<string, { tag: string; set_by: string; set_at: string | null }>;

const props = defineProps<{
  nodes: GraphNode[];
  links: GraphLink[];
  loading?: boolean;
  highlightedHubId?: string | null;
  nodeTags?: NodeTagMap;
}>();

const emit = defineEmits<{
  "node-click": [node: GraphNode];
  "hub-click": [hubId: string];
  "graph-click": [];
}>();

const chartContainer = ref<HTMLDivElement | null>(null);
let chart: echarts.ECharts | null = null;
let resizeObserver: ResizeObserver | null = null;
let pulseTimer: ReturnType<typeof setInterval> | null = null;
let pulsePhase = 0;

// Drag-pin state: nodes that the user has manually placed stay fixed
const fixedNodeIds = new Set<string>();
let dragNodeId: string | null = null;

// Compute highest severity of assets connected to each hub node
const hubHighestSeverity = computed(() => {
  const map: Record<string, string> = {};
  for (const link of props.links) {
    const srcNode = props.nodes.find((n) => n.id === link.source);
    const tgtNode = props.nodes.find((n) => n.id === link.target);
    // hub is the one without asset_id
    const [hub, asset] = srcNode?.detail?.asset_id ? [tgtNode, srcNode] : [srcNode, tgtNode];
    if (!hub || hub.detail?.asset_id) continue; // both are assets, skip
    const assetSev = String(asset?.detail?.highest_severity || asset?.severity || "info").toLowerCase();
    const existing = map[hub.id];
    if (!existing || (SEVERITY_RANK[assetSev] ?? 0) > (SEVERITY_RANK[existing] ?? 0)) {
      map[hub.id] = assetSev;
    }
  }
  return map;
});

const echartsData = computed(() => {
  const categories = [
    { name: "critical",   itemStyle: { color: SEVERITY_COLORS.critical } },
    { name: "high",       itemStyle: { color: SEVERITY_COLORS.high } },
    { name: "medium",     itemStyle: { color: SEVERITY_COLORS.medium } },
    { name: "low",        itemStyle: { color: SEVERITY_COLORS.low } },
    { name: "info",       itemStyle: { color: SEVERITY_COLORS.info } },
    { name: "hub-domain", itemStyle: { color: HUB_DOMAIN_COLOR } },
    { name: "hub-ip",     itemStyle: { color: HUB_IP_COLOR } },
  ];

  const categoryIndex: Record<string, number> = {};
  categories.forEach((c, i) => { categoryIndex[c.name] = i; });

  const highlightedHub = props.highlightedHubId;

  // Collect asset IDs connected to the highlighted hub
  const litAssetIds = new Set<string>();
  if (highlightedHub) {
    for (const link of props.links) {
      if (link.source === highlightedHub || link.target === highlightedHub) {
        const otherId = link.source === highlightedHub ? link.target : link.source;
        litAssetIds.add(otherId);
      }
    }
  }

  const nodes = props.nodes.map((n) => {
    const isHub = !n.detail?.asset_id;
    const sev = (n.severity || "").toLowerCase();

    // Base hub color depends on type (domain vs IP)
    const baseHubColor = isHub ? (isIpHub(n.name) ? HUB_IP_COLOR : HUB_DOMAIN_COLOR) : "";

    // Hub color: when highlighted → use its highest connected severity color; when another hub is highlighted → dim
    let hubColor = baseHubColor;
    let hubShadow = 0;
    if (isHub) {
      if (highlightedHub === n.id) {
        const topSev = hubHighestSeverity.value[n.id] || "info";
        hubColor = SEVERITY_COLORS[topSev] || SEVERITY_COLORS.info;
        hubShadow = 24;
      } else if (highlightedHub && highlightedHub !== n.id) {
        hubColor = "#2a3548"; // dimmed
      }
    }

    const catName = isHub
      ? (isIpHub(n.name) ? "hub-ip" : "hub-domain")
      : (sev in categoryIndex ? sev : "info");
    const sevColor = isHub ? hubColor : (SEVERITY_COLORS[sev] || "#94a3b8");

    let size = 36;
    if (isHub) {
      size = highlightedHub === n.id ? 26 : 18;
    } else if (sev === "critical") {
      size = 56;
    } else if (sev === "high") {
      size = 48;
    } else if (sev === "medium") {
      size = 40;
    }

    // Determine opacity: dim non-connected nodes when hub is selected
    let opacity = n.is_neighbor ? 0.45 : 1;
    if (highlightedHub) {
      if (!isHub) {
        if (!litAssetIds.has(n.id)) opacity = 0.15;
        else opacity = 1;
      } else if (isHub && highlightedHub !== n.id) {
        opacity = 0.2;
      }
    }

    // Gradient fill
    const isDimmedHub = hubColor === "#2a3548";
    const gradientColor = isHub
      ? { type: "radial" as const, x: 0.5, y: 0.35, r: 0.75, colorStops: [
          { offset: 0, color: isDimmedHub ? "#3a4558" : hubColor + "ee" },
          { offset: 1, color: isDimmedHub ? "#1a2234" : hubColor + "44" },
        ]}
      : { type: "radial" as const, x: 0.5, y: 0.35, r: 0.75, colorStops: [
          { offset: 0, color: sevColor + "ff" },
          { offset: 1, color: sevColor + "66" },
        ]};

    return {
      id: n.id,
      name: n.name,
      category: categoryIndex[catName] ?? 4,
      symbolSize: size,
      value: n,
      label: {
        show: !isHub,
        fontSize: n.is_neighbor ? 11 : 13,
        color: n.is_neighbor ? "rgba(255,255,255,0.4)" : "rgba(255,255,255,0.9)",
      },
      itemStyle: (() => {
        const nodeTag = props.nodeTags?.[n.id]?.tag;
        const tagColor = nodeTag ? TAG_COLORS[nodeTag] : null;
        // Tagged asset nodes get a thick colored border ring
        const baseBorderColor = isHub
          ? (highlightedHub === n.id
            ? (SEVERITY_COLORS[hubHighestSeverity.value[n.id] || "info"] + "cc")
            : (isDimmedHub ? "#2e3a4e" : hubColor + "99"))
          : "rgba(255,255,255,0.7)";
        return {
          color: gradientColor,
          opacity,
          borderColor: (!isHub && tagColor) ? tagColor : baseBorderColor,
          borderWidth: (!isHub && tagColor) ? 4 : (isHub ? (highlightedHub === n.id ? 2 : 1) : 2.5),
          borderType: (!isHub && tagColor) ? ("solid" as const) : ("solid" as const),
          shadowColor: isHub
            ? (hubShadow > 0 ? sevColor + "cc" : undefined)
            : (tagColor ? tagColor + "88" : `${sevColor}99`),
          shadowBlur: isHub ? hubShadow : (tagColor ? 22 : 18),
        };
      })(),
    };
  });

  const links = props.links.map((l) => {
    const isLit = highlightedHub
      ? (l.source === highlightedHub || l.target === highlightedHub)
      : true;
    const baseOpacity = l.relation === "shared-ip" ? 0.55 : 0.45;
    const opacity = highlightedHub ? (isLit ? 0.9 : 0.08) : baseOpacity;
    const width = highlightedHub && isLit ? 3 : (l.relation === "shared-ip" ? 2 : 1.5);
    return {
      source: l.source,
      target: l.target,
      value: l,
      lineStyle: {
        color: l.relation === "shared-ip"
          ? `rgba(34,211,238,${opacity})`
          : `rgba(168,85,247,${opacity})`,
        width,
        type: l.relation === "shared-ip" ? "solid" as const : "dashed" as const,
      },
    };
  });

  return { nodes, links, categories };
});

// Build a lookup from node ID → display name for edge tooltips
const nodeNameMap = computed(() => {
  const map: Record<string, string> = {};
  for (const n of props.nodes) {
    map[n.id] = n.name || n.id;
  }
  return map;
});

function buildOption() {
  const { nodes, links, categories } = echartsData.value;
  // Apply fixed positions for manually-pinned nodes so they don't drift back
  const finalNodes = fixedNodeIds.size > 0
    ? nodes.map((n: any) => {
        if (!fixedNodeIds.has(n.id)) return n;
        const pos = fixedPositions.get(n.id);
        return pos
          ? { ...n, fixed: true, x: pos.x, y: pos.y }
          : { ...n, fixed: true };
      })
    : nodes;
  return {
    backgroundColor: "transparent",
    tooltip: {
      show: true,
      enterable: false,
      appendToBody: true,
      borderColor: "rgba(255,255,255,0.08)",
      backgroundColor: "rgba(15,23,42,0.96)",
      textStyle: { color: "#e2e8f0", fontSize: 12 },
      formatter: (params: any) => {
        // Edge tooltip
        if (params.dataType === "edge") {
          const link = params.data?.value as GraphLink | undefined;
          const nameMap = nodeNameMap.value;
          const srcName = nameMap[params.data?.source] || params.data?.source || "?";
          const tgtName = nameMap[params.data?.target] || params.data?.target || "?";
          const relLabel = link?.relation === "shared-ip" ? "Shared IP" : "Root Domain";
          return `<div style="font-size:12px;color:#e2e8f0"><b>${srcName}</b> <span style="color:#94a3b8">⟷</span> <b>${tgtName}</b><br/><span style="color:#94a3b8;font-size:11px">${relLabel}</span></div>`;
        }
        // Node tooltip
        const node: GraphNode | undefined = params.data?.value;
        if (!node?.detail?.asset_id) {
          const hubSev = hubHighestSeverity.value[node?.id ?? ""] || null;
          const hubSevColor = hubSev ? (SEVERITY_COLORS[hubSev] || "#94a3b8") : "#94a3b8";
          return `<div style="font-size:13px;font-weight:700;color:#f1f5f9">${params.name}</div>${hubSev ? `<div style="margin-top:6px;display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:600;background:${hubSevColor}22;color:${hubSevColor};border:1px solid ${hubSevColor}44">Top: ${hubSev}</div>` : ""}<div style="margin-top:4px;font-size:11px;color:#64748b">Click to focus connected assets</div>`;
        }
        const d = node.detail;
        const sevColor = SEVERITY_COLORS[(d.highest_severity || "").toLowerCase()] || "#94a3b8";
        return `
          <div style="max-width:360px">
            <div style="font-weight:700;font-size:14px;color:#f1f5f9;margin-bottom:8px">${d.host}</div>
            <div style="display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:600;background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44;margin-bottom:8px">${d.highest_severity}</div>
            <div style="font-size:12px;color:#94a3b8;line-height:1.8">
              <b>IP:</b> <span style="color:#f1f5f9">${d.ip}</span><br/>
              <b>Ports:</b> <span style="color:#f1f5f9">${d.ports}</span><br/>
              <b>Finding Types:</b> <span style="color:#f1f5f9">${d.open_finding_types}</span><br/>
              <b>Vulns:</b> <span style="color:#f1f5f9">${d.vulnerability_count}</span>
              ${node.is_neighbor ? '<br/><span style="color:#f59e0b;font-style:italic">Neighbor (auto-discovered)</span>' : ''}
            </div>
          </div>`;
      },
    },
    series: [{
      type: "graph",
      layout: "force",
      roam: true,
      draggable: true,
      categories,
      data: finalNodes,
      links,
      force: {
        repulsion: 280,
        gravity: 0.06,
        friction: 0.32,
        edgeLength: [80, 200],
      },
      emphasis: {
        focus: "adjacency",
        lineStyle: { width: 3, color: "#f97316" },
      },
      label: {
        position: "bottom",
        distance: 6,
        fontFamily: "ui-monospace, monospace",
      },
      labelLayout: { hideOverlap: true },
      lineStyle: { curveness: 0.08 },
      edgeSymbol: ["none", "arrow"],
      edgeSymbolSize: 6,
    }],
  };
}

// Pulse animation: periodically nudge shadowBlur to create a living glow
function startPulse() {
  if (pulseTimer) return;
  pulseTimer = setInterval(() => {
    if (!chart) return;
    pulsePhase += 0.07;
    const pulse = Math.sin(pulsePhase); // -1 to 1
    const { nodes } = echartsData.value;
    // Preserve fixed positions so the pulse tick doesn't clear drag-pinned state
    const nodesWithFixed = fixedNodeIds.size > 0
      ? nodes.map((n: any) => {
          if (!fixedNodeIds.has(n.id)) return n;
          const pos = fixedPositions.get(n.id);
          return pos ? { ...n, fixed: true, x: pos.x, y: pos.y } : { ...n, fixed: true };
        })
      : nodes;
    chart.setOption({
      series: [{
        type: "graph",
        data: nodesWithFixed.map((n: any) => {
          const baseBlur = n.itemStyle?.shadowBlur ?? 0;
          if (baseBlur === 0) return n;
          return {
            ...n,
            itemStyle: {
              ...n.itemStyle,
              shadowBlur: baseBlur + pulse * 8,
            },
          };
        }),
      }],
    }, false);
  }, 60);
}

function stopPulse() {
  if (pulseTimer) { clearInterval(pulseTimer); pulseTimer = null; }
}

function initChart() {
  if (!chartContainer.value) return;
  chart = echarts.init(chartContainer.value, undefined, { renderer: "canvas" });
  chart.setOption(buildOption());

  chart.on("click", (params: any) => {
    if (params.dataType === "node") {
      const node: GraphNode | undefined = params.data?.value;
      if (node?.detail?.asset_id) {
        emit("node-click", node);
      } else if (node && !node.detail?.asset_id) {
        emit("hub-click", node.id);
      }
    }
  });

  // Drag-pin: on mouseup over a node, capture ALL node positions synchronously
  // (before any RAF tick can move them), then pin the dragged node in setTimeout(0).
  // The setTimeout fires before the next requestAnimationFrame tick, so the force
  // simulation never gets a chance to drift the node away from its drag-release spot.
  chart.on("mouseup", { dataType: "node" }, (params: any) => {
    const nodeId: string | undefined = params.data?.id;
    if (!nodeId || !chart) return;

    // Read ALL node layout positions right now — simulation hasn't ticked yet
    try {
      const seriesModel = (chart as any).getModel()?.getSeriesByIndex(0);
      const graph = seriesModel?.getGraph?.();
      if (graph) {
        graph.eachNode((gNode: any) => {
          const layout = gNode.getLayout?.();
          if (layout?.x !== undefined) {
            fixedPositions.set(gNode.id, { x: layout.x, y: layout.y });
          }
        });
      }
    } catch (_) { /* fall back: fixed:true without coords */ }

    // Apply AFTER ECharts' own drag handler has finished (still before next RAF)
    setTimeout(() => {
      if (!chart) return;
      fixedNodeIds.add(nodeId);
      chart.setOption(buildOption(), false);
    }, 0);
  });

  chart.getZr().on("click", (e: any) => {
    if (!e.target) {
      emit("graph-click");
    }
  });

  startPulse();
}

// Pixel-coord storage for accurately pinning dragged nodes
const fixedPositions = new Map<string, { x: number; y: number }>();

function updateChart(resetPins = false) {
  if (!chart) return;
  if (resetPins) {
    fixedNodeIds.clear();
    fixedPositions.clear();
  }
  // notMerge:true only on full data reload (resets force layout)
  // notMerge:false (merge) preserves node positions for highlight-only changes
  chart.setOption(buildOption(), { notMerge: resetPins });
}

watch(() => [props.nodes, props.links], () => {
  // New data from backend — reset pins and restart force layout
  if (chart) updateChart(true);
}, { deep: true });

watch(() => props.highlightedHubId, () => {
  // Only color/opacity change — keep pinned positions intact
  if (chart) updateChart(false);
});

watch(() => props.nodeTags, () => {
  // Tag changed — re-render borders without disturbing layout
  if (chart) updateChart(false);
}, { deep: true });

onMounted(() => {
  initChart();
  if (chartContainer.value) {
    resizeObserver = new ResizeObserver(() => chart?.resize());
    resizeObserver.observe(chartContainer.value);
  }
});

onBeforeUnmount(() => {
  stopPulse();
  resizeObserver?.disconnect();
  chart?.dispose();
  chart = null;
});
</script>

<template>
  <div class="relative h-full w-full">
    <div
      v-if="loading"
      class="absolute inset-0 z-10 flex items-center justify-center bg-slate-950/60 backdrop-blur-sm"
    >
      <p class="text-sm text-slate-400">Loading graph...</p>
    </div>
    <div
      v-if="!loading && nodes.length === 0"
      class="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3"
    >
      <p class="text-sm text-slate-400">No assets in this map yet.</p>
      <p class="text-xs text-slate-500">Click "+ Add Assets" to start building your campaign.</p>
    </div>
    <div ref="chartContainer" class="h-full w-full" />
  </div>
</template>
