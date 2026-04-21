<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppShell from "@/components/layout/AppShell.vue";
import HuntingMapAssetPicker from "@/components/hunting/HuntingMapAssetPicker.vue";
import HuntingMapGraph from "@/components/hunting/HuntingMapGraph.vue";
import HuntingMapVulnSidebar from "@/components/hunting/HuntingMapVulnSidebar.vue";
import api from "@/services/api";

import type { GraphNode, GraphLink } from "@/components/hunting/HuntingMapGraph.vue";

type MapMeta = {
  id: string;
  name: string;
  description: string;
  asset_ids: string[];
  asset_count: number;
  created_by: string;
  updated_at: string | null;
};

type GraphResponse = {
  nodes: GraphNode[];
  links: GraphLink[];
  stats: {
    total_assets: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

const route = useRoute();
const router = useRouter();
const mapId = computed(() => String(route.params.id || ""));

const mapMeta = ref<MapMeta | null>(null);
const nodes = ref<GraphNode[]>([]);
const links = ref<GraphLink[]>([]);
const stats = ref<GraphResponse["stats"]>({ total_assets: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
const graphLoading = ref(false);
const metaLoading = ref(false);
const refreshing = ref(false);
const lastRefreshed = ref<Date | null>(null);

const showAssetPicker = ref(false);
const selectedAssetId = ref<string | null>(null);
const selectedAssetHost = ref("");

const showEditModal = ref(false);
const editName = ref("");
const editDescription = ref("");
const editSaving = ref(false);

const removingAssets = ref(false);

const existingAssetIds = computed(() => mapMeta.value?.asset_ids ?? []);

const statCards = computed(() => [
  { label: "Assets", value: stats.value.total_assets, classes: "border-white/10 bg-white/[0.04] text-white" },
  { label: "Critical", value: stats.value.critical, classes: "border-[#ff0308]/25 bg-[#ff0308]/10 text-[#ff8a8d]" },
  { label: "High", value: stats.value.high, classes: "border-[#f36d14]/25 bg-[#f36d14]/10 text-[#ffb380]" },
  { label: "Medium", value: stats.value.medium, classes: "border-[#ffe240]/25 bg-[#ffe240]/10 text-[#fff09a]" },
  { label: "Low", value: stats.value.low, classes: "border-[#389e0d]/25 bg-[#389e0d]/10 text-[#abeb87]" },
  { label: "Info", value: stats.value.info, classes: "border-[#096dd9]/25 bg-[#096dd9]/10 text-[#68b0ff]" },
]);

function timeSince(date: Date | null) {
  if (!date) return "never";
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

async function fetchMeta() {
  metaLoading.value = true;
  try {
    const { data } = await api.get<MapMeta>(`/hunting-maps/${encodeURIComponent(mapId.value)}`);
    mapMeta.value = data;
  } catch {
    await router.push({ name: "hunting-maps" });
  } finally {
    metaLoading.value = false;
  }
}

async function fetchGraph() {
  graphLoading.value = true;
  try {
    const { data } = await api.get<GraphResponse>(`/hunting-maps/${encodeURIComponent(mapId.value)}/graph`);
    nodes.value = data.nodes ?? [];
    links.value = data.links ?? [];
    stats.value = data.stats ?? { total_assets: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    lastRefreshed.value = new Date();
  } catch (error) {
    console.error(error);
  } finally {
    graphLoading.value = false;
  }
}

async function refreshMap() {
  refreshing.value = true;
  try {
    await api.post(`/hunting-maps/${encodeURIComponent(mapId.value)}/refresh`);
    await fetchGraph();
  } catch (error) {
    console.error(error);
  } finally {
    refreshing.value = false;
  }
}

async function addAssets(assetIds: string[]) {
  showAssetPicker.value = false;
  try {
    await api.post(`/hunting-maps/${encodeURIComponent(mapId.value)}/assets`, { asset_ids: assetIds });
    await Promise.all([fetchMeta(), fetchGraph()]);
  } catch (error) {
    console.error(error);
  }
}

async function removeSelectedAsset() {
  if (!selectedAssetId.value) return;
  removingAssets.value = true;
  try {
    await api.delete(`/hunting-maps/${encodeURIComponent(mapId.value)}/assets`, {
      data: { asset_ids: [selectedAssetId.value] },
    });
    selectedAssetId.value = null;
    selectedAssetHost.value = "";
    await Promise.all([fetchMeta(), fetchGraph()]);
  } catch (error) {
    console.error(error);
  } finally {
    removingAssets.value = false;
  }
}

function onNodeClick(node: GraphNode) {
  if (node.is_neighbor) return;
  if (selectedAssetId.value === node.detail?.asset_id) {
    selectedAssetId.value = null;
    selectedAssetHost.value = "";
    return;
  }
  selectedAssetId.value = node.detail?.asset_id ?? null;
  selectedAssetHost.value = node.detail?.host ?? node.name;
}

function dismissSidebar() {
  selectedAssetId.value = null;
  selectedAssetHost.value = "";
}

// Fullscreen
const isFullscreen = ref(false);
const graphSection = ref<HTMLElement | null>(null);

function toggleFullscreen() {
  if (!document.fullscreenElement) {
    (graphSection.value ?? document.documentElement).requestFullscreen?.();
  } else {
    document.exitFullscreen?.();
  }
}

function onFullscreenChange() {
  isFullscreen.value = !!document.fullscreenElement;
}

// Hub highlight
const highlightedHubId = ref<string | null>(null);

function onHubClick(hubId: string) {
  // Toggle: clicking same hub again clears highlight
  highlightedHubId.value = highlightedHubId.value === hubId ? null : hubId;
}

function openEditModal() {
  if (!mapMeta.value) return;
  editName.value = mapMeta.value.name;
  editDescription.value = mapMeta.value.description;
  showEditModal.value = true;
}

async function saveEdit() {
  editSaving.value = true;
  try {
    await api.patch(`/hunting-maps/${encodeURIComponent(mapId.value)}`, {
      name: editName.value.trim(),
      description: editDescription.value.trim(),
    });
    showEditModal.value = false;
    await fetchMeta();
  } catch (error) {
    console.error(error);
  } finally {
    editSaving.value = false;
  }
}

function handleEscape(e: KeyboardEvent) {
  if (e.key === "Escape") {
    if (showAssetPicker.value) { showAssetPicker.value = false; return; }
    if (showEditModal.value) { showEditModal.value = false; return; }
    if (selectedAssetId.value) { dismissSidebar(); }
  }
}

onMounted(async () => {
  window.addEventListener("keydown", handleEscape);
  document.addEventListener("fullscreenchange", onFullscreenChange);
  await fetchMeta();
  await fetchGraph();
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", handleEscape);
  document.removeEventListener("fullscreenchange", onFullscreenChange);
});
</script>

<template>
  <AppShell
    eyebrow="T&W Falcon"
    :title="mapMeta?.name || 'Hunting Map'"
    :description="mapMeta?.description || 'Loading...'"
  >
    <!-- Toolbar -->
    <section class="mt-4 rounded-[1.25rem] border border-white/10 bg-slate-900/65 px-5 py-3 backdrop-blur-xl">
      <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="router.push({ name: 'hunting-maps' })"
          >
            ← Back to Maps
          </button>
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="openEditModal"
          >
            Edit Info
          </button>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <!-- Stats -->
          <span
            v-for="s in statCards"
            :key="s.label"
            class="rounded-full border px-3 py-1 text-xs font-semibold"
            :class="s.classes"
          >
            {{ s.label }}: {{ s.value }}
          </span>

          <span class="text-xs text-slate-500">
            Updated {{ timeSince(lastRefreshed) }}
          </span>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="rounded-full border border-orange-400/20 bg-orange-400/10 px-4 py-2 text-xs font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18"
            @click="showAssetPicker = true"
          >
            + Add Assets
          </button>

          <button
            v-if="selectedAssetId"
            type="button"
            class="rounded-full border border-red-400/20 bg-red-500/10 px-4 py-2 text-xs font-semibold text-red-200 transition hover:border-red-400/35 hover:bg-red-500/18 disabled:opacity-50"
            :disabled="removingAssets"
            @click="removeSelectedAsset"
          >
            {{ removingAssets ? 'Removing...' : 'Remove Asset' }}
          </button>

          <button
            type="button"
            class="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:border-cyan-400/35 hover:bg-cyan-400/18 disabled:opacity-50"
            :disabled="refreshing"
            @click="refreshMap"
          >
            {{ refreshing ? 'Refreshing...' : '↻ Refresh' }}
          </button>
        </div>
      </div>
    </section>

    <!-- Graph + Sidebar workspace -->
    <section
      ref="graphSection"
      class="relative mt-4 overflow-hidden rounded-[1.6rem] border border-white/10 bg-slate-950/70 backdrop-blur-xl"
      style="height: calc(100vh - 16rem)"
    >
      <HuntingMapGraph
        :nodes="nodes"
        :links="links"
        :loading="graphLoading"
        :highlighted-hub-id="highlightedHubId"
        @node-click="onNodeClick"
        @graph-click="dismissSidebar"
        @hub-click="onHubClick"
      />

      <HuntingMapVulnSidebar
        :map-id="mapId"
        :asset-id="selectedAssetId"
        :asset-host="selectedAssetHost"
        @close="dismissSidebar"
      />

      <!-- Legend -->
      <div class="absolute left-4 top-4 z-20 rounded-[1rem] border border-white/10 bg-slate-950/85 px-4 py-3 backdrop-blur">
        <p class="text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-500">Legend</p>
        <div class="mt-2 space-y-1.5">
          <div class="flex items-center gap-2 text-xs text-slate-300">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#ff0308;box-shadow:0 0 8px #ff030888" /> Critical
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-300">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#f36d14;box-shadow:0 0 6px #f36d1488" /> High
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-300">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#ffe240" /> Medium
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-300">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#389e0d" /> Low
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-300">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#096dd9" /> Info
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-400">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#7c3aed;box-shadow:0 0 6px #7c3aed66" /> Hub (domain)
          </div>
          <div class="flex items-center gap-2 text-xs text-slate-400">
            <span class="inline-block h-3 w-3 rounded-full" style="background:#0891b2;box-shadow:0 0 6px #0891b266" /> Hub (IP)
          </div>
          <div class="mt-1 flex items-center gap-2 text-xs text-slate-500">
            <span class="inline-block h-3 w-3 rounded-full border border-dashed border-slate-500 bg-transparent opacity-50" /> Neighbor (auto)
          </div>
        </div>
      </div>

      <!-- Fullscreen button -->
      <button
        type="button"
        class="absolute right-4 top-4 z-20 flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-slate-950/85 text-slate-300 backdrop-blur transition hover:border-white/20 hover:bg-white/[0.08] hover:text-white"
        :title="isFullscreen ? 'Exit fullscreen' : 'Fullscreen'"
        @click="toggleFullscreen"
      >
        <!-- Expand icon -->
        <svg v-if="!isFullscreen" xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4 8V5a1 1 0 0 1 1-1h3M4 16v3a1 1 0 0 0 1 1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3" />
        </svg>
        <!-- Compress icon -->
        <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M8 4v4H4M4 16h4v4M16 4v4h4M20 16h-4v4" />
        </svg>
      </button>
    </section>

    <!-- Asset Picker modal -->
    <HuntingMapAssetPicker
      :visible="showAssetPicker"
      :existing-asset-ids="existingAssetIds"
      @close="showAssetPicker = false"
      @add="addAssets"
    />

    <!-- Edit Map modal -->
    <div
      v-if="showEditModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/78 px-4 py-6 backdrop-blur-sm"
      @click.self="showEditModal = false"
    >
      <div class="w-full max-w-lg rounded-[1.6rem] border border-white/10 bg-slate-900 p-6 shadow-2xl shadow-black/40">
        <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Edit Campaign</p>
        <h3 class="mt-2 text-xl font-semibold text-white">Update Hunting Map</h3>

        <label class="mt-5 block rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
          Campaign Name
          <input
            v-model="editName"
            type="text"
            class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition focus:border-orange-400/35"
            @keydown.enter="saveEdit"
          >
        </label>

        <label class="mt-3 block rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
          Description
          <textarea
            v-model="editDescription"
            rows="3"
            class="mt-2 w-full resize-none rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition focus:border-orange-400/35"
          />
        </label>

        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="showEditModal = false"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-full border border-orange-400/20 bg-orange-400/10 px-5 py-2 text-sm font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="!editName.trim() || editSaving"
            @click="saveEdit"
          >
            {{ editSaving ? 'Saving...' : 'Save' }}
          </button>
        </div>
      </div>
    </div>
  </AppShell>
</template>
