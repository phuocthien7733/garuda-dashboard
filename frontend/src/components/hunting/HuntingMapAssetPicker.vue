<script setup lang="ts">
import { ref, watch } from "vue";

import api from "@/services/api";

type AssetRecord = {
  id: string;
  host: string;
  ip_addresses: string[];
  open_ports: string[];
  highest_severity?: string | null;
  vulnerability_count: number;
};

const props = defineProps<{
  visible: boolean;
  existingAssetIds: string[];
}>();

const emit = defineEmits<{
  close: [];
  add: [assetIds: string[]];
}>();

const searchQuery = ref("");
const results = ref<AssetRecord[]>([]);
const loading = ref(false);
const selectedIds = ref<string[]>([]);
let debounceTimer: number | undefined;

function severityClasses(value: unknown) {
  const n = String(value ?? "").toLowerCase();
  if (n === "critical") return "border border-[#ff0308]/35 bg-[#ff0308]/10 text-[#ff8083]";
  if (n === "high") return "border border-[#f36d14]/35 bg-[#f36d14]/10 text-[#f8a15e]";
  if (n === "medium") return "border border-[#ffe240]/35 bg-[#ffe240]/10 text-[#ffe97a]";
  if (n === "low") return "border border-[#389e0d]/35 bg-[#389e0d]/10 text-[#8fd46d]";
  if (n === "info") return "border border-[#096dd9]/35 bg-[#096dd9]/10 text-[#68b0ff]";
  return "border border-white/10 bg-white/[0.04] text-slate-300";
}

async function searchAssets() {
  loading.value = true;
  try {
    const { data } = await api.get("/assets", {
      params: {
        search: searchQuery.value.trim() || undefined,
        page_size: 50,
      },
    });
    results.value = (data.items ?? []).filter(
      (a: AssetRecord) => !props.existingAssetIds.includes(a.id),
    );
  } catch (error) {
    console.error(error);
    results.value = [];
  } finally {
    loading.value = false;
  }
}

function toggleSelection(id: string) {
  if (selectedIds.value.includes(id)) {
    selectedIds.value = selectedIds.value.filter((i) => i !== id);
  } else {
    selectedIds.value = [...selectedIds.value, id];
  }
}

function confirm() {
  if (selectedIds.value.length === 0) return;
  emit("add", [...selectedIds.value]);
  selectedIds.value = [];
}

watch(() => props.visible, (v) => {
  if (v) {
    searchQuery.value = "";
    selectedIds.value = [];
    searchAssets();
  }
});

watch(searchQuery, () => {
  if (debounceTimer) window.clearTimeout(debounceTimer);
  debounceTimer = window.setTimeout(searchAssets, 300);
});
</script>

<template>
  <div
    v-if="visible"
    class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/78 px-4 py-6 backdrop-blur-sm"
    @click.self="emit('close')"
  >
    <div class="flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-[1.6rem] border border-white/10 bg-slate-900 shadow-2xl shadow-black/40">

      <!-- Header -->
      <div class="border-b border-white/10 px-6 py-5">
        <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Asset Picker</p>
        <h3 class="mt-2 text-xl font-semibold text-white">Add Assets to Hunting Map</h3>

        <label class="mt-4 block">
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search by host, IP, domain..."
            class="w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-sm font-medium text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
          >
        </label>
      </div>

      <!-- Results -->
      <div class="flex-1 overflow-y-auto">
        <div v-if="loading" class="px-6 py-8 text-center text-sm text-slate-400">
          Searching assets...
        </div>

        <div v-else-if="results.length === 0" class="px-6 py-8 text-center text-sm text-slate-400">
          No matching assets found.
        </div>

        <table v-else class="min-w-full divide-y divide-white/6 text-sm">
          <thead>
            <tr class="text-left text-xs uppercase tracking-[0.24em] text-slate-500">
              <th class="px-4 py-2.5 w-10"></th>
              <th class="px-4 py-2.5">Host</th>
              <th class="px-4 py-2.5">IP</th>
              <th class="px-4 py-2.5">Severity</th>
              <th class="px-4 py-2.5">Vulns</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr
              v-for="asset in results"
              :key="asset.id"
              class="cursor-pointer transition hover:bg-white/[0.03]"
              :class="selectedIds.includes(asset.id) ? 'bg-orange-400/[0.06]' : ''"
              @click="toggleSelection(asset.id)"
            >
              <td class="px-4 py-3">
                <input
                  type="checkbox"
                  class="h-4 w-4 rounded border-white/15 bg-white/[0.04] text-orange-400 focus:ring-orange-400"
                  :checked="selectedIds.includes(asset.id)"
                  @click.stop
                  @change="toggleSelection(asset.id)"
                >
              </td>
              <td class="px-4 py-3 font-semibold text-white">{{ asset.host }}</td>
              <td class="px-4 py-3 text-slate-300">{{ asset.ip_addresses?.join(', ') || '--' }}</td>
              <td class="px-4 py-3">
                <span
                  v-if="asset.highest_severity"
                  class="inline-flex rounded-full px-3 py-0.5 text-xs font-semibold uppercase tracking-[0.2em]"
                  :class="severityClasses(asset.highest_severity)"
                >
                  {{ asset.highest_severity }}
                </span>
                <span v-else class="text-slate-500">--</span>
              </td>
              <td class="px-4 py-3 text-slate-300">{{ asset.vulnerability_count }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Footer -->
      <div class="flex items-center justify-between border-t border-white/10 px-6 py-4">
        <span class="text-sm text-slate-400">
          {{ selectedIds.length }} asset{{ selectedIds.length !== 1 ? 's' : '' }} selected
        </span>
        <div class="flex gap-2">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="emit('close')"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-full border border-orange-400/20 bg-orange-400/10 px-5 py-2 text-sm font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="selectedIds.length === 0"
            @click="confirm"
          >
            Add {{ selectedIds.length }} Asset{{ selectedIds.length !== 1 ? 's' : '' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
