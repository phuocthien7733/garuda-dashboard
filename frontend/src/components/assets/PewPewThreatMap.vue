<script setup lang="ts">
import * as echarts from "echarts";
import worldGeoJson from "geojson-world-map/lib/world.js";
import { nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import api from "@/services/api";

type MapNode = {
  ip: string;
  lat: number;
  lon: number;
  severity: "Critical" | "High" | "Medium" | "Low";
  provider: string;
  asset_count: number;
  city?: string;
  country?: string;
};

type MapResponse = {
  nodes: MapNode[];
  generated_at?: string;
};

const router = useRouter();
const chartElement = ref<HTMLDivElement | null>(null);
const isLoading = ref(false);
const errorMessage = ref("");
const nodeCount = ref(0);
const lastGeneratedAt = ref<string | null>(null);

let chart: echarts.ECharts | null = null;
let resizeObserver: ResizeObserver | null = null;
let resizeAfterMountTimer: number | undefined;
let denseHydrationTimer: number | undefined;
let worldMapLoaded = false;
let resizeRafId: number | null = null;

function handleShellResize() {
  scheduleResize();
}

function scheduleResize() {
  if (!chart) {
    return;
  }
  if (resizeRafId !== null) {
    window.cancelAnimationFrame(resizeRafId);
  }
  resizeRafId = window.requestAnimationFrame(() => {
    chart?.resize();
    resizeRafId = null;
  });
}

const severityColor: Record<MapNode["severity"], string> = {
  Critical: "#ff0308ff",
  High: "#f36d14ff",
  Medium: "#ffe240ff",
  Low: "#ffe240ff",
};

function formatGeneratedAt(value: string | null) {
  if (!value) {
    return "Live stream";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Live stream";
  }
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const yyyy = date.getUTCFullYear();
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const min = String(date.getUTCMinutes()).padStart(2, "0");
  return `${dd}-${mm}-${yyyy} ${hh}:${min} UTC`;
}

function buildSeries(nodes: MapNode[]) {
  const normalNodes = nodes.filter((node) => node.severity !== "Critical");
  const criticalNodes = nodes.filter((node) => node.severity === "Critical");

  const toMapPoint = (node: MapNode) => ({
    name: node.ip,
    value: [node.lon, node.lat, Math.max(node.asset_count, 1)],
    ...node,
    itemStyle: {
      color: severityColor[node.severity],
      shadowBlur: node.severity === "High" ? 22 : 18,
      shadowColor: severityColor[node.severity],
      borderColor: "rgba(255,255,255,0.74)",
      borderWidth: 0.6,
    },
    symbolSize: Math.min(30, 7 + Math.log2(Math.max(node.asset_count, 1) + 1) * 5),
  });

  return [
    {
      name: "Threat Nodes",
      type: "scatter",
      coordinateSystem: "geo",
      zlevel: 2,
      encode: { value: 2 },
      data: normalNodes.map(toMapPoint),
      emphasis: {
        scale: 1.2,
      },
    },
    {
      name: "Critical Aura",
      type: "effectScatter",
      coordinateSystem: "geo",
      zlevel: 4,
      showEffectOn: "render",
      rippleEffect: {
        period: 3.2,
        scale: 4.4,
        brushType: "stroke",
      },
      symbolSize: (value: number[]) => Math.min(36, 10 + Math.log2(Math.max(value?.[2] || 1, 1) + 1) * 7),
      data: criticalNodes.map(toMapPoint),
      itemStyle: {
        color: severityColor.Critical,
        shadowBlur: 42,
        shadowColor: "rgba(255, 3, 8, 0.82)",
      },
      emphasis: {
        scale: 1.25,
      },
    },
  ];
}

function tooltipFormatter(params: any) {
  if (!params?.data) {
    return "";
  }
  const point = params.data as MapNode;
  return `
    <div style="min-width:270px;border:1px solid rgba(148,163,184,.2);background:rgba(2,6,23,.96);backdrop-filter:blur(8px);border-radius:14px;padding:12px 14px;color:#e2e8f0;box-shadow:0 16px 30px rgba(0,0,0,.45);">
      <div style="font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#94a3b8;font-weight:700;">Threat Beacon</div>
      <div style="margin-top:8px;font-size:16px;color:#fff;font-weight:700;">${point.ip}</div>
      <div style="margin-top:10px;display:grid;grid-template-columns:auto 1fr;gap:6px 10px;font-size:12px;line-height:1.45;">
        <span style="color:#94a3b8;font-weight:700;">Location</span><span>${point.city || "Unknown City"}, ${point.country || "Unknown Country"}</span>
        <span style="color:#94a3b8;font-weight:700;">Provider</span><span>${point.provider || "Unknown Provider"}</span>
        <span style="color:#94a3b8;font-weight:700;">Severity</span><span style="font-weight:800;color:${severityColor[point.severity]};">${point.severity}</span>
        <span style="color:#94a3b8;font-weight:700;">Assets</span><span>${point.asset_count}</span>
      </div>
      <div style="margin-top:10px;color:#7dd3fc;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;">Click to open inventory by IP</div>
    </div>
  `;
}

function renderMap(nodes: MapNode[]) {
  if (!chartElement.value) {
    return;
  }

  if (!chart) {
    chart = echarts.init(chartElement.value);
  }

  chart.off("click");
  chart.on("click", (params: any) => {
    if (params?.componentType !== "series" || !params?.data?.ip) {
      return;
    }
    const target = router.resolve({
      name: "assets",
      query: {
        search: params.data.ip,
      },
    });
    window.open(target.href, "_blank", "noopener,noreferrer");
  });

  chart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      borderWidth: 0,
      padding: 0,
      backgroundColor: "transparent",
      formatter: tooltipFormatter,
    },
    geo: {
      map: "world",
      roam: true,
      zoom: 1.16,
      center: [8, 22],
      layoutCenter: ["50%", "54%"],
      layoutSize: "165%",
      aspectScale: 1,
      selectedMode: false,
      itemStyle: {
        areaColor: "rgba(38, 57, 86, 0.86)",
        borderColor: "rgba(125, 211, 252, 0.42)",
        borderWidth: 1.1,
      },
      emphasis: {
        disabled: false,
        itemStyle: {
          areaColor: "rgba(71, 104, 148, 0.92)",
          borderColor: "rgba(186, 230, 253, 0.72)",
          borderWidth: 1.3,
        },
      },
    },
    visualMap: {
      show: false,
      min: 1,
      max: Math.max(20, ...nodes.map((node) => node.asset_count)),
      calculable: false,
      inRange: {
        symbolSize: [8, 26],
      },
    },
    series: buildSeries(nodes),
  });
}

async function ensureWorldMap() {
  if (worldMapLoaded || echarts.getMap("world")) {
    worldMapLoaded = true;
    return;
  }

  const rawMap = (worldGeoJson as { default?: unknown })?.default ?? worldGeoJson;
  const featureCollection =
    rawMap && typeof rawMap === "object" && "features" in (rawMap as Record<string, unknown>)
      ? rawMap
      : null;

  if (!featureCollection) {
    throw new Error("World GeoJSON payload is invalid.");
  }

  echarts.registerMap("world", featureCollection as any);
  worldMapLoaded = true;
}

async function loadMapData(limit = 240, background = false) {
  if (!background) {
    isLoading.value = true;
    errorMessage.value = "";
  }
  try {
    await ensureWorldMap();
    const { data } = await api.get<MapResponse>("/map-data", {
      params: {
        limit,
      },
    });
    const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
    if (background && nodes.length <= nodeCount.value) {
      return;
    }
    nodeCount.value = nodes.length;
    lastGeneratedAt.value = data?.generated_at || null;
    await nextTick();
    renderMap(nodes);
  } catch (error) {
    console.error(error);
    if (!background) {
      errorMessage.value = "Unable to load tactical map data.";
    }
  } finally {
    if (!background) {
      isLoading.value = false;
    }
  }
}

onMounted(() => {
  void loadMapData(240, false);
  denseHydrationTimer = window.setTimeout(() => {
    void loadMapData(520, true);
  }, 1200);
  if (chartElement.value) {
    resizeObserver = new ResizeObserver(() => scheduleResize());
    resizeObserver.observe(chartElement.value);
  }
  window.addEventListener("easm-sidebar-change", handleShellResize);
  resizeAfterMountTimer = window.setTimeout(() => scheduleResize(), 420);
});

onBeforeUnmount(() => {
  resizeObserver?.disconnect();
  resizeObserver = null;
  if (resizeAfterMountTimer) {
    window.clearTimeout(resizeAfterMountTimer);
  }
  if (denseHydrationTimer) {
    window.clearTimeout(denseHydrationTimer);
  }
  if (resizeRafId !== null) {
    window.cancelAnimationFrame(resizeRafId);
    resizeRafId = null;
  }
  window.removeEventListener("easm-sidebar-change", handleShellResize);
  chart?.dispose();
  chart = null;
});
</script>

<template>
  <section class="mt-4 rounded-[1.75rem] border border-white/10 bg-slate-900/65 p-4 backdrop-blur">
    <div class="flex flex-col gap-2 border-b border-white/10 pb-4 md:flex-row md:items-center md:justify-between">
      <div>
        <h2 class="text-xl font-semibold text-white">PewPew Global Threat Map</h2>
        <p class="mt-1 text-sm text-slate-400">Cyber threat geolocation with neon tactical beacons for Red Team situational awareness.</p>
      </div>
      <div class="flex items-center gap-2 text-xs uppercase tracking-[0.16em] text-slate-300">
        <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1">Nodes: {{ nodeCount }}</span>
        <span class="rounded-full border border-cyan-300/20 bg-cyan-500/8 px-3 py-1 text-cyan-100">{{ formatGeneratedAt(lastGeneratedAt) }}</span>
      </div>
    </div>

    <div
      class="relative mt-4 w-full overflow-hidden rounded-[1.35rem] border border-white/10"
      style="
        height: 30rem;
        width: 100%;
        background:
          radial-gradient(circle at 20% 18%, rgba(6, 182, 212, 0.14), transparent 36%),
          radial-gradient(circle at 78% 66%, rgba(236, 72, 153, 0.14), transparent 38%),
          linear-gradient(180deg, rgba(2, 6, 23, 0.96), rgba(2, 6, 23, 0.9)),
          repeating-linear-gradient(0deg, rgba(148, 163, 184, 0.08) 0, rgba(148, 163, 184, 0.08) 1px, transparent 1px, transparent 28px),
          repeating-linear-gradient(90deg, rgba(148, 163, 184, 0.08) 0, rgba(148, 163, 184, 0.08) 1px, transparent 1px, transparent 28px);
      "
    >
      <div ref="chartElement" class="h-full w-full" />

      <div v-if="isLoading" class="absolute inset-0 flex items-center justify-center bg-slate-950/45 text-sm font-semibold tracking-[0.12em] text-cyan-200">
        STREAMING THREAT INTEL...
      </div>
      <div v-else-if="errorMessage" class="absolute inset-0 flex items-center justify-center bg-slate-950/45 text-sm font-semibold text-rose-200">
        {{ errorMessage }}
      </div>
    </div>
  </section>
</template>
