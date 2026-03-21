<script setup lang="ts">
import * as echarts from "echarts";
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";

type MenuItem = {
  name: string;
  label: string;
  description: string;
  iconPath: string;
  route?: { name: string };
  adminOnly?: boolean;
};

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

type TopAssetItem = {
  id?: string | null;
  host: string;
  count: number;
  highest_severity?: string | null;
};

type TrendResponse = {
  days: number;
  labels: string[];
  series: {
    critical: number[];
    high: number[];
    medium: number[];
    low: number[];
    info: number[];
  };
};

type TechStackItem = {
  name: string;
  host_count: number;
};

const authStore = useAuthStore();
const route = useRoute();
const router = useRouter();
const sidebarExpanded = ref(localStorage.getItem("easm_sidebar_expanded") !== "false");
const chartElement = ref<HTMLDivElement | null>(null);
const trendChartElement = ref<HTMLDivElement | null>(null);
const techStackChartElement = ref<HTMLDivElement | null>(null);
const selectedAssetSeverity = ref<SeverityFilter>("all");
const topAssets = ref<TopAssetItem[]>([]);
const techStackData = ref<TechStackItem[]>([]);
const trendData = ref<TrendResponse>({
  days: 7,
  labels: [],
  series: {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  },
});
const stats = ref({
  assets: 0,
  open_vulnerabilities: 0,
  critical_vulnerabilities: 0,
  high_vulnerabilities: 0,
  medium_vulnerabilities: 0,
  low_vulnerabilities: 0,
  info_vulnerabilities: 0,
  open_severity_distribution: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
});

const menuItems: MenuItem[] = [
  {
    name: "dashboard",
    label: "Overview",
    description: "Main dashboard",
    route: { name: "dashboard" },
    iconPath: "M3 13.5 12 4l9 9M5.25 11.25V20h13.5v-8.75",
  },
  {
    name: "assets",
    label: "Assets",
    description: "Asset inventory",
    route: { name: "assets" },
    iconPath: "M3.75 4.5h16.5v4.5H3.75zM5.25 9v10.5h13.5V9M9 13.5h6",
  },
  {
    name: "users",
    label: "Users",
    description: "Admin only",
    route: { name: "users" },
    adminOnly: true,
    iconPath: "M16 19v-1a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v1M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M20 8v6M23 11h-6",
  },
];

const visibleMenuItems = computed(() => {
  return menuItems.filter((item) => !item.adminOnly || authStore.isAdmin);
});
const topAssetMaxCount = computed(() => Math.max(...topAssets.value.map((item) => item.count), 1));

let reloadTimer: number | undefined;
let resizeTimer: number | undefined;
let severityChart: echarts.ECharts | null = null;
let trendChart: echarts.ECharts | null = null;
let techStackChart: echarts.ECharts | null = null;
let chartResizeObserver: ResizeObserver | null = null;

function scheduleChartResize() {
  if (resizeTimer) {
    window.clearTimeout(resizeTimer);
  }
  resizeTimer = window.setTimeout(() => {
    severityChart?.resize();
    trendChart?.resize();
    techStackChart?.resize();
  }, 320);
}

function handleShellResize() {
  scheduleChartResize();
}

const severityPalette = {
  critical: "#ff0308ff",
  high: "#f36d14ff",
  medium: "#ffe240ff",
  low: "#389e0d",
  info: "#096dd9",
};

function renderSeverityChart() {
  if (!chartElement.value) {
    return;
  }

  if (!severityChart) {
    severityChart = echarts.init(chartElement.value);
  }

  const distribution = stats.value.open_severity_distribution;
  const pieData = [
    { name: "Critical", value: distribution.critical, itemStyle: { color: severityPalette.critical } },
    { name: "High", value: distribution.high, itemStyle: { color: severityPalette.high } },
    { name: "Medium", value: distribution.medium, itemStyle: { color: severityPalette.medium } },
    { name: "Low", value: distribution.low, itemStyle: { color: severityPalette.low } },
    { name: "Info", value: distribution.info, itemStyle: { color: severityPalette.info } },
  ].filter((item) => item.value > 0);

  severityChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(2, 6, 23, 0.96)",
      borderColor: "rgba(148, 163, 184, 0.18)",
      textStyle: {
        color: "#e2e8f0",
      },
      formatter: "{b}: {c} ({d}%)",
    },
    series: [
      {
        name: "Open Vulnerabilities",
        type: "pie",
        radius: ["62%", "92%"],
        center: ["50%", "46%"],
        avoidLabelOverlap: true,
        label: {
          color: "#e2e8f0",
          formatter: "{b}\n{d}%",
          fontWeight: 600,
        },
        labelLine: {
          lineStyle: {
            color: "rgba(203, 213, 225, 0.35)",
          },
        },
        itemStyle: {
          borderColor: "#0f172a",
          borderWidth: 3,
        },
        data: pieData.length > 0 ? pieData : [{ name: "No Open Vulns", value: 1, itemStyle: { color: "rgba(148,163,184,0.25)" } }],
      },
    ],
    graphic:
      pieData.length > 0
        ? [
            {
              type: "text",
              left: "center",
              top: "36%",
              style: {
                text: String(stats.value.open_vulnerabilities),
                fill: "#ffffff",
                fontSize: 32,
                fontWeight: 700,
                textAlign: "center",
              },
            },
            {
              type: "text",
              left: "center",
              top: "50%",
              style: {
                text: "OPEN",
                fill: "#94a3b8",
                fontSize: 11,
                fontWeight: 700,
                textAlign: "center",
                letterSpacing: 2,
              },
            },
          ]
        : [
            {
              type: "text",
              left: "center",
              top: "40%",
              style: {
                text: "No open vulnerabilities",
                fill: "#94a3b8",
                fontSize: 14,
                fontWeight: 600,
                textAlign: "center",
              },
            },
          ],
  });

  severityChart.off("click");
  severityChart.on("click", (params) => {
    const severityName = String(params.name ?? "").toLowerCase();
    const supportedSeverities = new Set(["critical", "high", "medium", "low", "info"]);

    if (!supportedSeverities.has(severityName) || Number(params.value ?? 0) <= 0) {
      return;
    }

    const target = router.resolve({
      name: "vulnerabilities",
      query: {
        severity: severityName,
        status: "Open",
      },
    });

    window.open(target.href, "_blank", "noopener,noreferrer");
  });
}

function renderTrendChart() {
  if (!trendChartElement.value) {
    return;
  }

  if (!trendChart) {
    trendChart = echarts.init(trendChartElement.value);
  }

  trendChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      backgroundColor: "rgba(2, 6, 23, 0.96)",
      borderColor: "rgba(148, 163, 184, 0.18)",
      textStyle: {
        color: "#e2e8f0",
      },
    },
    legend: {
      top: 0,
      right: 0,
      icon: "circle",
      textStyle: {
        color: "#cbd5e1",
        fontSize: 12,
      },
    },
    grid: {
      left: 18,
      right: 18,
      top: 44,
      bottom: 18,
      containLabel: true,
    },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: trendData.value.labels,
      axisLine: {
        lineStyle: {
          color: "rgba(148, 163, 184, 0.22)",
        },
      },
      axisLabel: {
        color: "#94a3b8",
        fontSize: 11,
        formatter: (value: string) => {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
            return value;
          }
          return `${value.slice(8, 10)}-${value.slice(5, 7)}`;
        },
      },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      splitLine: {
        lineStyle: {
          color: "rgba(148, 163, 184, 0.12)",
        },
      },
      axisLabel: {
        color: "#94a3b8",
        fontSize: 11,
      },
    },
    series: [
      {
        name: "Critical",
        type: "line",
        smooth: true,
        showSymbol: true,
        symbol: "circle",
        symbolSize: 8,
        color: severityPalette.critical,
        itemStyle: {
          color: severityPalette.critical,
        },
        lineStyle: {
          width: 3,
          color: severityPalette.critical,
        },
        areaStyle: {
          color: "rgba(255, 3, 8, 0.14)",
        },
        data: trendData.value.series.critical,
      },
      {
        name: "High",
        type: "line",
        smooth: true,
        showSymbol: true,
        symbol: "circle",
        symbolSize: 8,
        color: severityPalette.high,
        itemStyle: {
          color: severityPalette.high,
        },
        lineStyle: {
          width: 3,
          color: severityPalette.high,
        },
        areaStyle: {
          color: "rgba(243, 109, 20, 0.12)",
        },
        data: trendData.value.series.high,
      },
      {
        name: "Medium",
        type: "line",
        smooth: true,
        showSymbol: true,
        symbol: "circle",
        symbolSize: 8,
        color: severityPalette.medium,
        itemStyle: {
          color: severityPalette.medium,
        },
        lineStyle: {
          width: 3,
          color: severityPalette.medium,
        },
        areaStyle: {
          color: "rgba(255, 226, 64, 0.12)",
        },
        data: trendData.value.series.medium,
      },
      {
        name: "Low",
        type: "line",
        smooth: true,
        showSymbol: true,
        symbol: "circle",
        symbolSize: 7,
        color: severityPalette.low,
        itemStyle: {
          color: severityPalette.low,
        },
        lineStyle: {
          width: 2,
          color: severityPalette.low,
        },
        areaStyle: {
          color: "rgba(56, 158, 13, 0.10)",
        },
        data: trendData.value.series.low,
      },
      {
        name: "Info",
        type: "line",
        smooth: true,
        showSymbol: true,
        symbol: "circle",
        symbolSize: 7,
        color: severityPalette.info,
        itemStyle: {
          color: severityPalette.info,
        },
        lineStyle: {
          width: 2,
          color: severityPalette.info,
        },
        areaStyle: {
          color: "rgba(9, 109, 217, 0.10)",
        },
        data: trendData.value.series.info,
      },
    ],
  });

  trendChart.off("click");
  trendChart.on("click", (params) => {
    if (params.componentType !== "series") {
      return;
    }

    const dateLabel = String(params.name ?? "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateLabel)) {
      return;
    }

    const severityName = String(params.seriesName ?? "").toLowerCase();
    const supportedSeverities = new Set(["critical", "high", "medium", "low", "info"]);
    if (!supportedSeverities.has(severityName)) {
      return;
    }

    const target = router.resolve({
      name: "vulnerabilities",
      query: {
        severity: severityName,
        timeField: "first_seen",
        dateFrom: dateLabel,
        dateTo: dateLabel,
      },
    });

    window.open(target.href, "_blank", "noopener,noreferrer");
  });
}

function formatTechLabel(name: string) {
  return name
    .replace(/\s*-\s*Detect$/i, "")
    .replace(/\s+Detection$/i, "")
    .replace(/\s+detect$/i, "")
    .replace(/\s+version$/i, "")
    .replace(/\s+version detect$/i, "")
    .replace(/\s+End-of-Life$/i, "")
    .replace(/\s+API$/i, "")
    .trim();
}

function renderTechStackChart() {
  if (!techStackChartElement.value) {
    return;
  }

  if (!techStackChart) {
    techStackChart = echarts.init(techStackChartElement.value);
  }

  const colorPool = [
    "#ff0308ff",
    "#f36d14ff",
    "#ffe240ff",
    "#389e0d",
    "#096dd9",
    "#fb7185",
    "#14b8a6",
    "#a3e635",
    "#f59e0b",
    "#60a5fa",
  ];

  const treemapData = techStackData.value.map((item, index) => ({
    name: formatTechLabel(item.name),
    value: item.host_count,
    itemStyle: {
      color: colorPool[index % colorPool.length],
      borderColor: "rgba(15, 23, 42, 0.95)",
      borderWidth: 3,
      gapWidth: 3,
    },
  }));

  techStackChart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      formatter: ({ name, value }: { name: string; value: number }) => `${name}: ${value} hosts`,
      backgroundColor: "rgba(2, 6, 23, 0.96)",
      borderColor: "rgba(148, 163, 184, 0.18)",
      textStyle: {
        color: "#e2e8f0",
      },
    },
    series: [
      {
        type: "treemap",
        roam: false,
        nodeClick: false,
        left: 2,
        right: 2,
        top: 2,
        bottom: 2,
        breadcrumb: {
          show: false,
        },
        label: {
          show: true,
          formatter: "{b}\n{c}",
          color: "#ffffff",
          fontWeight: 700,
          fontSize: 11,
        },
        upperLabel: {
          show: false,
        },
        itemStyle: {
          borderColor: "rgba(15, 23, 42, 0.95)",
          borderWidth: 2,
          gapWidth: 2,
        },
        data: treemapData,
      },
    ],
    graphic:
      treemapData.length === 0
        ? [
            {
              type: "text",
              left: "center",
              top: "45%",
              style: {
                text: "No technology findings available",
                fill: "#94a3b8",
                fontSize: 14,
                fontWeight: 600,
                textAlign: "center",
              },
            },
          ]
        : [],
  });

  techStackChart.off("click");
  techStackChart.on("click", (params) => {
    if (params.componentType !== "series") {
      return;
    }

    const techName = String(params.name ?? "").trim();
    if (!techName) {
      return;
    }

    const target = router.resolve({
      name: "vulnerabilities",
      query: {
        search: techName,
      },
    });

    window.open(target.href, "_blank", "noopener,noreferrer");
  });
}

async function loadTopAssets() {
  try {
    const { data } = await api.get("/assets/top", {
      params: {
        severity: selectedAssetSeverity.value,
      },
    });
    topAssets.value = data;
  } catch (error) {
    console.error(error);
  }
}

async function loadTrendData() {
  try {
    const { data } = await api.get("/stats/trend", {
      params: {
        days: 7,
      },
    });
    trendData.value = data;
    await nextTick();
    renderTrendChart();
  } catch (error) {
    console.error(error);
  }
}

async function loadTechStack() {
  try {
    const { data } = await api.get("/stats/tech-stack");
    techStackData.value = data;
    await nextTick();
    renderTechStackChart();
  } catch (error) {
    console.error(error);
  }
}

async function loadStats() {
  try {
    const { data } = await api.get("/stats");
    stats.value = data;
    await nextTick();
    renderSeverityChart();
  } catch (error) {
    console.error(error);
  }
}

function toggleSidebar() {
  sidebarExpanded.value = !sidebarExpanded.value;
  localStorage.setItem("easm_sidebar_expanded", String(sidebarExpanded.value));
}

function isActive(item: MenuItem) {
  return route.name === item.name;
}

async function navigateTo(item: MenuItem) {
  if (item.route) {
    await router.push(item.route);
  }
}

async function logout() {
  try {
    await api.post("/auth/logout");
  } catch (error) {
    console.error(error);
  } finally {
    authStore.clearSession();
    router.push({ name: "login" });
  }
}

async function openAssetDetail(asset: TopAssetItem) {
  if (!asset.id) {
    return;
  }

  const target = router.resolve({
    name: "asset-profile",
    params: { id: asset.id },
  });

  window.open(target.href, "_blank", "noopener,noreferrer");
}

onMounted(() => {
  loadStats();
  loadTopAssets();
  loadTrendData();
  loadTechStack();
  reloadTimer = window.setInterval(() => window.location.reload(), 2 * 60 * 60 * 1000);
  window.addEventListener("resize", renderSeverityChart);
  window.addEventListener("resize", renderTrendChart);
  window.addEventListener("resize", renderTechStackChart);
  window.addEventListener("easm-sidebar-change", handleShellResize);

  chartResizeObserver = new ResizeObserver(() => {
    scheduleChartResize();
  });

  [chartElement.value, trendChartElement.value, techStackChartElement.value]
    .filter((element): element is HTMLDivElement => Boolean(element))
    .forEach((element) => chartResizeObserver?.observe(element));
});

onBeforeUnmount(() => {
  if (reloadTimer) {
    window.clearInterval(reloadTimer);
  }
  if (resizeTimer) {
    window.clearTimeout(resizeTimer);
  }
  window.removeEventListener("resize", renderSeverityChart);
  window.removeEventListener("resize", renderTrendChart);
  window.removeEventListener("resize", renderTechStackChart);
  window.removeEventListener("easm-sidebar-change", handleShellResize);
  chartResizeObserver?.disconnect();
  chartResizeObserver = null;
  severityChart?.dispose();
  trendChart?.dispose();
  techStackChart?.dispose();
  severityChart = null;
  trendChart = null;
  techStackChart = null;
});

watch(selectedAssetSeverity, () => {
  loadTopAssets();
});
</script>

<template>
  <AppShell eyebrow="T&W Falcon" title="External Attack Surface Management">
        <section class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <article class="rounded-[1.5rem] border border-white/10 bg-white/5 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Assets</p>
            <p class="mt-3 text-4xl font-bold text-white">{{ stats.assets }}</p>
          </article>
          <article class="rounded-[1.5rem] border border-white/10 bg-white/5 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Open Vulns</p>
            <p class="mt-3 text-4xl font-bold text-white">{{ stats.open_vulnerabilities }}</p>
          </article>
          <article class="rounded-[1.5rem] border p-4 backdrop-blur" style="border-color: rgba(255, 3, 8, 0.28); background: rgba(255, 3, 8, 0.08);">
            <p class="text-xs uppercase tracking-[0.22em]" style="color: #ff0308ff;">Critical</p>
            <p class="mt-3 text-4xl font-bold" style="color: #ffd9da;">{{ stats.critical_vulnerabilities }}</p>
          </article>
          <article class="rounded-[1.5rem] border p-4 backdrop-blur" style="border-color: rgba(243, 109, 20, 0.28); background: rgba(243, 109, 20, 0.08);">
            <p class="text-xs uppercase tracking-[0.22em]" style="color: #f36d14ff;">High</p>
            <p class="mt-3 text-4xl font-bold" style="color: #ffd9c5;">{{ stats.high_vulnerabilities }}</p>
          </article>
          <article class="rounded-[1.5rem] border p-4 backdrop-blur" style="border-color: rgba(255, 226, 64, 0.28); background: rgba(255, 226, 64, 0.08);">
            <p class="text-xs uppercase tracking-[0.22em]" style="color: #ffe240ff;">Medium</p>
            <p class="mt-3 text-4xl font-bold" style="color: #fff5b8;">{{ stats.medium_vulnerabilities }}</p>
          </article>
        </section>

        <section class="mt-4 grid gap-4 xl:grid-cols-2">
          <div class="min-h-[24rem] rounded-[1.75rem] border border-white/10 bg-slate-900/60 p-5 backdrop-blur">
            <div class="flex items-center justify-between gap-4">
              <div>
                <h2 class="text-xl font-semibold text-white">Priority Overview</h2>
                <p class="mt-1 text-sm text-slate-400">Open vulnerability distribution by severity across the current attack surface.</p>
              </div>
            </div>

            <div class="mt-5 h-[24rem] rounded-[1.4rem] border border-white/10 bg-slate-950/55 p-2">
              <div ref="chartElement" class="h-full w-full" />
            </div>
          </div>

          <div class="min-h-[24rem] rounded-[1.75rem] border border-white/10 bg-slate-900/60 p-5 backdrop-blur">
            <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 class="text-xl font-semibold text-white">Top Exposed Assets</h2>
                <p class="mt-1 text-sm text-slate-400">Top 5 assets ranked by open vulnerability count for the selected severity.</p>
              </div>
              <label class="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-2 text-xs uppercase tracking-[0.18em] text-slate-300">
                <span>Severity</span>
                <select v-model="selectedAssetSeverity" class="bg-transparent text-xs font-semibold uppercase text-white outline-none">
                  <option value="all" class="bg-slate-900">All</option>
                  <option value="critical" class="bg-slate-900">Critical</option>
                  <option value="high" class="bg-slate-900">High</option>
                  <option value="medium" class="bg-slate-900">Medium</option>
                  <option value="low" class="bg-slate-900">Low</option>
                  <option value="info" class="bg-slate-900">Info</option>
                </select>
              </label>
            </div>
            <div class="mt-5 rounded-[1.4rem] border border-white/10 bg-slate-950/45 p-4">
              <div v-if="topAssets.length === 0" class="flex h-[18.5rem] items-center justify-center text-center text-sm text-slate-500">
                No matching open vulnerabilities for the selected severity.
              </div>
              <div v-else class="space-y-3">
                <article
                  v-for="(asset, index) in topAssets"
                  :key="asset.host"
                  class="cursor-pointer rounded-[1rem] border border-white/8 bg-white/[0.025] p-3 transition hover:border-orange-400/20 hover:bg-orange-400/[0.05]"
                  :title="`Open asset detail for ${asset.host}`"
                  @click="openAssetDetail(asset)"
                >
                  <div class="flex items-center gap-3">
                    <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-white/10 bg-slate-900 text-xs font-bold text-slate-300">
                      {{ index + 1 }}
                    </span>
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center justify-between gap-3">
                        <p class="truncate text-sm font-semibold text-white">{{ asset.host }}</p>
                        <span class="text-sm font-bold text-slate-200">{{ asset.count }}</span>
                      </div>
                      <div class="mt-2 h-2 rounded-full bg-white/6">
                        <div
                          class="h-full rounded-full"
                          :style="{
                            width: `${(asset.count / topAssetMaxCount) * 100}%`,
                            backgroundColor:
                              asset.highest_severity === 'critical'
                                ? '#ff0308ff'
                                : asset.highest_severity === 'high'
                                  ? '#f36d14ff'
                                  : asset.highest_severity === 'medium'
                                    ? '#ffe240ff'
                                    : asset.highest_severity === 'low'
                                      ? '#389e0d'
                                      : '#096dd9',
                          }"
                        />
                      </div>
                    </div>
                  </div>
                </article>
              </div>
            </div>
          </div>
        </section>

        <section class="mt-4 grid gap-4 xl:grid-cols-2">
          <div class="min-h-[23rem] rounded-[1.75rem] border border-white/10 bg-slate-900/60 p-5 backdrop-blur">
            <div class="flex items-center justify-between gap-4">
              <div>
                <h2 class="text-xl font-semibold text-white">Attack Surface Trend</h2>
                <p class="mt-1 text-sm text-slate-400">New vulnerabilities discovered over the last 7 days, separated into individual severity timelines.</p>
              </div>
            </div>

            <div class="mt-4 h-[18.5rem] rounded-[1.4rem] border border-white/10 bg-slate-950/55 p-2">
              <div ref="trendChartElement" class="h-full w-full" />
            </div>
          </div>

          <div class="min-h-[24.5rem] rounded-[1.75rem] border border-white/10 bg-slate-900/60 p-4 backdrop-blur">
            <div class="flex items-center justify-between gap-4">
              <div>
                <h2 class="text-xl font-semibold text-white">Exposed Tech Stack</h2>
                <p class="mt-1 text-sm text-slate-400">Technologies observed on internet-facing hosts based on informational detection findings.</p>
              </div>
            </div>

            <div class="mt-3 h-[20.5rem] rounded-[1.4rem] border border-white/10 bg-slate-950/55 p-0.5">
              <div ref="techStackChartElement" class="h-full w-full" />
            </div>
          </div>
        </section>
  </AppShell>
</template>
