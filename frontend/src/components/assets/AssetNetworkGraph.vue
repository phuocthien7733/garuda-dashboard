<script setup lang="ts">
import * as echarts from "echarts";
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";

import api from "@/services/api";

type NetworkNode = {
  id: string;
  name: string;
  category: string;
  detail?: {
    asset_id?: string | null;
    ip?: string;
    host?: string;
    ports?: string;
    services?: string;
    tech?: string;
    highest_severity?: string;
  };
};

type NetworkLink = {
  source: string;
  target: string;
  relation?: string;
};

type NetworkResponse = {
  nodes: NetworkNode[];
  links: NetworkLink[];
};

const props = defineProps<{
  assetId: string;
}>();

const router = useRouter();
const chartElement = ref<HTMLDivElement | null>(null);
const loading = ref(false);
const errorMessage = ref("");
const showTooltip = ref(false);

let chart: echarts.ECharts | null = null;

type CategoryStyle = {
  color: string;
  shadowColor: string;
  symbolSize: number;
  borderColor: string;
  borderWidth: number;
};

const categoryStyles: Record<string, CategoryStyle> = {
  focus_host: {
    color: "#ff0308",
    shadowColor: "rgba(255, 3, 8, 0.75)",
    symbolSize: 84,
    borderColor: "rgba(255, 236, 236, 0.95)",
    borderWidth: 3,
  },
  root_domain: {
    color: "#a855f7",
    shadowColor: "rgba(168, 85, 247, 0.62)",
    symbolSize: 50,
    borderColor: "rgba(233, 213, 255, 0.8)",
    borderWidth: 2,
  },
  shared_ip: {
    color: "#22d3ee",
    shadowColor: "rgba(34, 211, 238, 0.58)",
    symbolSize: 42,
    borderColor: "rgba(207, 250, 254, 0.78)",
    borderWidth: 2,
  },
  related_domain: {
    color: "#8b5cf6",
    shadowColor: "rgba(139, 92, 246, 0.48)",
    symbolSize: 46,
    borderColor: "rgba(221, 214, 254, 0.76)",
    borderWidth: 2,
  },
  related_ip: {
    color: "#06b6d4",
    shadowColor: "rgba(6, 182, 212, 0.48)",
    symbolSize: 48,
    borderColor: "rgba(165, 243, 252, 0.76)",
    borderWidth: 2,
  },
  related_both: {
    color: "#f36d14",
    shadowColor: "rgba(243, 109, 20, 0.6)",
    symbolSize: 54,
    borderColor: "rgba(255, 237, 213, 0.82)",
    borderWidth: 2,
  },
};

function escapeHtml(value: unknown) {
  return String(value ?? "--")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function truncateLabel(value: string) {
  return value.length > 28 ? `${value.slice(0, 25)}...` : value;
}

function severityBadgeHtml(value: unknown) {
  const severity = String(value ?? '--').toLowerCase();
  const palette: Record<string, { bg: string; border: string; text: string }> = {
    critical: { bg: 'rgba(255, 3, 8, 0.14)', border: 'rgba(255, 3, 8, 0.38)', text: '#ff9ea1' },
    high: { bg: 'rgba(243, 109, 20, 0.14)', border: 'rgba(243, 109, 20, 0.38)', text: '#ffc08d' },
    medium: { bg: 'rgba(255, 226, 64, 0.14)', border: 'rgba(255, 226, 64, 0.4)', text: '#fff1a3' },
    low: { bg: 'rgba(56, 158, 13, 0.14)', border: 'rgba(56, 158, 13, 0.36)', text: '#b7ef8f' },
    info: { bg: 'rgba(9, 109, 217, 0.14)', border: 'rgba(9, 109, 217, 0.36)', text: '#91caff' },
  };

  const style = palette[severity] || { bg: 'rgba(148, 163, 184, 0.12)', border: 'rgba(148, 163, 184, 0.28)', text: '#e2e8f0' };
  return `<span style="display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;border:1px solid ${style.border};background:${style.bg};color:${style.text};font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;box-shadow:0 0 18px ${style.bg};">${escapeHtml(severity)}</span>`;
}

function openAssetDetailInNewTab(assetId: string | null | undefined) {
  if (!assetId) {
    return;
  }
  const href = router.resolve({ name: 'asset-profile', params: { id: assetId } }).href;
  window.open(href, '_blank', 'noopener');
}

function normalizeNodes(nodes: NetworkNode[]) {
  return nodes.map((node) => {
    const style = categoryStyles[node.category] || categoryStyles.related_domain;
    return {
      ...node,
      symbol: "circle",
      symbolSize: style.symbolSize,
      draggable: true,
      label: {
        show: true,
        formatter: truncateLabel(node.name),
        color: "#f8fafc",
        fontWeight: node.category === "focus_host" ? 700 : 600,
        fontSize: node.category === "focus_host" ? 13 : 11,
        lineHeight: 15,
      },
      itemStyle: {
        color: style.color,
        borderColor: style.borderColor,
        borderWidth: style.borderWidth,
        shadowBlur: node.category === "focus_host" ? 55 : 30,
        shadowColor: style.shadowColor,
      },
      emphasis: {
        scale: true,
        label: {
          color: "#ffffff",
        },
        itemStyle: {
          shadowBlur: node.category === "focus_host" ? 70 : 44,
          shadowColor: style.shadowColor,
        },
      },
    };
  });
}

function normalizeLinks(links: NetworkLink[]) {
  return links.map((link) => ({
    ...link,
    lineStyle: {
      color: "rgba(148, 163, 184, 0.2)",
      width: 1.3,
      opacity: 0.9,
      curveness: 0.08,
    },
    emphasis: {
      lineStyle: {
        color: "rgba(255, 255, 255, 0.72)",
        width: 2.4,
        opacity: 1,
      },
    },
  }));
}

function tooltipFormatter(params: any) {
  if (params.dataType !== "node") {
    return `<div style="padding:6px 8px;color:#e2e8f0;">Relation: ${escapeHtml(params.data?.relation || "linked")}</div>`;
  }

  const node = params.data as NetworkNode;
  const detail = node.detail || {};
  const detailAssetId = detail.asset_id ? escapeHtml(detail.asset_id) : "";
  const detailAction = detailAssetId
    ? `<a href="/assets/${detailAssetId}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;justify-content:center;padding:9px 14px;border-radius:999px;border:1px solid rgba(34,211,238,.28);background:linear-gradient(135deg, rgba(34,211,238,.16), rgba(56,189,248,.08));color:#d9faff;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;text-decoration:none;box-shadow:0 0 18px rgba(34,211,238,.16);transition:all .18s ease;">View Detail Asset</a>`
    : `<span style="display:inline-flex;align-items:center;justify-content:center;padding:9px 14px;border-radius:999px;border:1px solid rgba(148,163,184,.18);background:rgba(148,163,184,.08);color:#94a3b8;font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;">Infrastructure Node</span>`;

  return `
    <div style="min-width:260px;border:1px solid rgba(148,163,184,.18);background:rgba(2,6,23,.96);backdrop-filter:blur(12px);border-radius:16px;padding:14px 16px;color:#e2e8f0;box-shadow:0 20px 40px rgba(0,0,0,.45);">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
        <div>
          <div style="font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#94a3b8;font-weight:700;">Tactical Node</div>
          <div style="margin-top:8px;font-size:16px;font-weight:700;color:#fff;">${escapeHtml(node.name)}</div>
        </div>
        <div style="flex-shrink:0;">${detailAction}</div>
      </div>
      <div style="margin-top:10px;display:grid;gap:8px;font-size:12px;line-height:1.55;">
        <div><span style="color:#94a3b8;font-weight:700;">Host:</span> <span style="color:#f8fafc;">${escapeHtml(detail.host)}</span></div>
        <div style="display:flex;align-items:center;gap:10px;"><span style="color:#94a3b8;font-weight:700;">Highest Severity:</span> ${severityBadgeHtml(detail.highest_severity)}</div>
        <div><span style="color:#94a3b8;font-weight:700;">IP:</span> <span style="color:#f8fafc;">${escapeHtml(detail.ip)}</span></div>
        <div><span style="color:#94a3b8;font-weight:700;">Ports:</span> <span style="color:#f8fafc;">${escapeHtml(detail.ports)}</span></div>
        <div><span style="color:#94a3b8;font-weight:700;">Services:</span> <span style="color:#f8fafc;">${escapeHtml(detail.services)}</span></div>
        <div><span style="color:#94a3b8;font-weight:700;">Tech:</span> <span style="color:#f8fafc;">${escapeHtml(detail.tech)}</span></div>
      </div>
    </div>
  `;
}

function renderChart(payload: NetworkResponse) {
  if (!chartElement.value) {
    return;
  }

  if (!chart) {
    chart = echarts.init(chartElement.value);
  }

  const nodes = normalizeNodes(payload.nodes || []);
  const links = normalizeLinks(payload.links || []);

  chart.off("click");
  chart.on("click", (params: any) => {
    if (params.dataType !== "node") {
      return;
    }

    const assetId = params.data?.detail?.asset_id;
    if (!assetId) {
      return;
    }

    openAssetDetailInNewTab(assetId);
  });

  chart.setOption({
    backgroundColor: "transparent",
    animationDuration: 1200,
    animationEasingUpdate: "cubicOut",
    tooltip: {
      trigger: "item",
      show: showTooltip.value,
      enterable: true,
      appendToBody: true,
      borderWidth: 0,
      padding: 0,
      backgroundColor: "transparent",
      formatter: tooltipFormatter,
      position(point, _params, _dom, _rect, size) {
        const [mouseX, mouseY] = point as number[];
        const [contentWidth, contentHeight] = size.contentSize as number[];
        const [viewWidth, viewHeight] = size.viewSize as number[];
        const offsetX = 22;
        const offsetY = 18;

        let left = mouseX + offsetX;
        let top = mouseY - contentHeight / 2;

        if (left + contentWidth > viewWidth - 12) {
          left = mouseX - contentWidth - offsetX;
        }
        if (left < 12) {
          left = 12;
        }

        if (top + contentHeight > viewHeight - 12) {
          top = viewHeight - contentHeight - 12;
        }
        if (top < 12) {
          top = 12;
        }

        return [left, top + offsetY / 4];
      },
    },
    graphic: nodes.length
      ? []
      : [
          {
            type: "text",
            left: "center",
            top: "middle",
            style: {
              text: "No related assets or shared infrastructure found.",
              fill: "#94a3b8",
              fontSize: 14,
              fontWeight: 600,
              textAlign: "center",
            },
          },
        ],
    series: [
      {
        type: "graph",
        layout: "force",
        data: nodes,
        links,
        roam: true,
        draggable: true,
        focusNodeAdjacency: true,
        edgeSymbol: ["none", "none"],
        lineStyle: {
          color: "rgba(148, 163, 184, 0.22)",
          width: 1.2,
          opacity: 0.85,
          curveness: 0.08,
        },
        emphasis: {
          focus: "adjacency",
          lineStyle: {
            color: "rgba(255,255,255,0.88)",
            width: 2.4,
            opacity: 1,
          },
        },
        force: {
          repulsion: 320,
          gravity: 0.07,
          friction: 0.35,
          edgeLength: [90, 175],
          layoutAnimation: true,
        },
        coolDownTime: 1000,
        labelLayout: {
          hideOverlap: true,
        },
      },
    ],
  });
}

async function loadNetwork() {
  if (!props.assetId) {
    return;
  }

  loading.value = true;
  errorMessage.value = "";
  let payload: NetworkResponse | null = null;

  try {
    const { data } = await api.get<NetworkResponse>(`/assets/${encodeURIComponent(props.assetId)}/network`);
    payload = data;
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail || "Unable to load the asset network graph.";
  } finally {
    loading.value = false;
  }

  if (!payload || errorMessage.value) {
    return;
  }

  await nextTick();
  renderChart(payload);
  chart?.resize();
}

function handleResize() {
  chart?.resize();
}

watch(
  () => props.assetId,
  async () => {
    await loadNetwork();
  },
);

watch(showTooltip, (value) => {
  if (!chart) {
    return;
  }
  chart.setOption({
    tooltip: {
      show: value,
    },
  });
  if (!value) {
    chart.dispatchAction({ type: "hideTip" });
  }
});

onMounted(async () => {
  await loadNetwork();
  window.addEventListener("resize", handleResize);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", handleResize);
  chart?.dispose();
  chart = null;
});
</script>

<template>
  <section class="mt-4 rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur-xl">
    <div class="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Attack Paths</p>
        <h3 class="mt-2 text-xl font-semibold text-white">Asset Spider Network</h3>
        <p class="mt-1 text-sm text-slate-400">
          Force-directed reconnaissance map of root-domain and shared-IP relationships around this asset.
        </p>
      </div>
      <span class="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">
        Tactical map
      </span>
    </div>

    <div class="network-grid mt-5 overflow-hidden rounded-[1.4rem] border border-white/10 bg-slate-950/75 p-2">
      <div v-if="loading" class="flex h-[28rem] items-center justify-center text-sm text-slate-400">
        Building tactical network graph...
      </div>
      <div v-else-if="errorMessage" class="flex h-[28rem] items-center justify-center px-6 text-center text-sm text-red-200">
        {{ errorMessage }}
      </div>
      <div v-else ref="chartElement" class="h-[28rem] w-full" />
    </div>

    <div class="mt-4 flex flex-wrap items-center justify-between gap-3">
      <label class="inline-flex items-center gap-3 rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-300">
        <input
          v-model="showTooltip"
          type="checkbox"
          class="h-4 w-4 rounded border-white/15 bg-white/[0.04] text-cyan-400 focus:ring-cyan-400"
        >
        Display Tooltip
      </label>
      <p class="text-xs text-slate-500">
        Turn tooltip off to freely drag and arrange nodes without visual obstruction.
      </p>
    </div>

    <div class="mt-4 flex flex-wrap gap-2 text-xs text-slate-400">
      <span class="rounded-full border border-[#ff0308]/20 bg-[#ff0308]/10 px-3 py-1 text-[#ffb0b2]">Focus Host</span>
      <span class="rounded-full border border-[#a855f7]/20 bg-[#a855f7]/10 px-3 py-1 text-[#dfb8ff]">Root Domain</span>
      <span class="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-cyan-200">Shared IP</span>
      <span class="rounded-full border border-[#8b5cf6]/20 bg-[#8b5cf6]/10 px-3 py-1 text-[#ddd6fe]">Related Domain</span>
      <span class="rounded-full border border-[#06b6d4]/20 bg-[#06b6d4]/10 px-3 py-1 text-[#a5f3fc]">Related IP</span>
      <span class="rounded-full border border-[#f36d14]/20 bg-[#f36d14]/10 px-3 py-1 text-[#ffd6b8]">Shared Root + IP</span>
    </div>
  </section>
</template>

<style scoped>
.network-grid {
  background-image:
    linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px),
    radial-gradient(circle at top, rgba(14, 165, 233, 0.08), transparent 40%),
    radial-gradient(circle at bottom, rgba(239, 68, 68, 0.08), transparent 36%);
  background-size: 24px 24px, 24px 24px, 100% 100%, 100% 100%;
  background-position: center;
}
</style>
