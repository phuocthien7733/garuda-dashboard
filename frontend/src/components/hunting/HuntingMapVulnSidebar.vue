<script setup lang="ts">
import { computed, ref, watch } from "vue";

import VulnerabilityDetailModal from "@/components/vulnerabilities/VulnerabilityDetailModal.vue";
import api from "@/services/api";

type VulnerabilityRecord = {
  id?: string;
  fingerprint?: string;
  name?: string;
  severity?: string;
  override_severity?: string | null;
  ip?: string | null;
  host?: string | null;
  port?: string | number | null;
  matched_at?: string | null;
  template_id?: string | null;
  source_tool_first?: string | null;
  status?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  request?: string | null;
  response?: string | null;
  "curl-command"?: string | null;
  curl_command?: string | null;
  [key: string]: unknown;
};

const PAGE_SIZE = 5;

const props = defineProps<{
  mapId: string;
  assetId: string | null;
  assetHost: string;
  currentTag?: string | null;
}>();

const emit = defineEmits<{
  close: [];
  'set-tag': [tag: string];
  'remove-tag': [];
}>();

const vulnerabilities = ref<VulnerabilityRecord[]>([]);
const total = ref(0);
const loading = ref(false);
const selectedVuln = ref<VulnerabilityRecord | null>(null);
const copiedSection = ref<"request" | "response" | "curl" | null>(null);
const searchQuery = ref("");
const currentPage = ref(1);
const archivingId = ref<string | null>(null);

// Filtered list (client-side search)
const filtered = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) return vulnerabilities.value;
  return vulnerabilities.value.filter((v) => {
    const name = String(v.name ?? "").toLowerCase();
    const sev = String(v.override_severity || v.severity || "").toLowerCase();
    const ip = String(v.ip ?? "").toLowerCase();
    const tmpl = String(v.template_id ?? "").toLowerCase();
    const tool = String(v.source_tool_first ?? "").toLowerCase();
    return name.includes(q) || sev.includes(q) || ip.includes(q) || tmpl.includes(q) || tool.includes(q);
  });
});

const totalPages = computed(() => Math.max(1, Math.ceil(filtered.value.length / PAGE_SIZE)));

const paginatedVulns = computed(() => {
  const start = (currentPage.value - 1) * PAGE_SIZE;
  return filtered.value.slice(start, start + PAGE_SIZE);
});

// Reset page when search changes
watch(searchQuery, () => { currentPage.value = 1; });

function severityClasses(value: unknown) {
  const n = String(value ?? "").toLowerCase();
  if (n === "critical") return "border border-[#ff0308]/35 bg-[#ff0308]/10 text-[#ff8083]";
  if (n === "high") return "border border-[#f36d14]/35 bg-[#f36d14]/10 text-[#f8a15e]";
  if (n === "medium") return "border border-[#ffe240]/35 bg-[#ffe240]/10 text-[#ffe97a]";
  if (n === "low") return "border border-[#389e0d]/35 bg-[#389e0d]/10 text-[#8fd46d]";
  if (n === "info") return "border border-[#096dd9]/35 bg-[#096dd9]/10 text-[#68b0ff]";
  return "border border-white/10 bg-white/[0.04] text-slate-300";
}

function effectiveSeverity(v: VulnerabilityRecord) {
  return String(v.override_severity || v.severity || "unknown");
}

function formatDate(value: unknown) {
  if (!value) return "--";
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) return String(value);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}-${pad(d.getMonth() + 1)}-${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function fetchVulnerabilities() {
  if (!props.assetId || !props.mapId) return;
  loading.value = true;
  try {
    const { data } = await api.get(`/hunting-maps/${encodeURIComponent(props.mapId)}/assets/${encodeURIComponent(props.assetId)}/vulnerabilities`, {
      params: { page_size: 200 },
    });
    vulnerabilities.value = data.items ?? [];
    total.value = data.total ?? 0;
  } catch (error) {
    console.error(error);
    vulnerabilities.value = [];
    total.value = 0;
  } finally {
    loading.value = false;
  }
}

async function archiveVuln(v: VulnerabilityRecord) {
  const fprint = v.fingerprint || v.id;
  if (!fprint) return;
  archivingId.value = fprint;
  try {
    await api.post(`/vulns/${encodeURIComponent(fprint)}/archive`);
    // Remove from local list
    vulnerabilities.value = vulnerabilities.value.filter((x) => (x.fingerprint || x.id) !== fprint);
    total.value = Math.max(0, total.value - 1);
    // If current page is now empty but not the first page, go back
    if (paginatedVulns.value.length === 0 && currentPage.value > 1) {
      currentPage.value--;
    }
  } catch (error) {
    console.error(error);
  } finally {
    archivingId.value = null;
  }
}

function openVulnDetail(v: VulnerabilityRecord) {
  selectedVuln.value = v;
  copiedSection.value = null;
}

function closeVulnDetail() {
  selectedVuln.value = null;
  copiedSection.value = null;
}

async function copyContent(section: "request" | "response" | "curl", value: unknown) {
  const text = String(value ?? "");
  if (!text || text === "--") return;
  try {
    await navigator.clipboard.writeText(text);
    copiedSection.value = section;
    window.setTimeout(() => {
      if (copiedSection.value === section) copiedSection.value = null;
    }, 1800);
  } catch (error) {
    console.error(error);
  }
}

watch(() => props.assetId, (newVal) => {
  selectedVuln.value = null;
  copiedSection.value = null;
  searchQuery.value = "";
  currentPage.value = 1;
  if (newVal) fetchVulnerabilities();
  else {
    vulnerabilities.value = [];
    total.value = 0;
  }
}, { immediate: true });
</script>

<template>
  <Transition name="slide-up">
    <div
      v-if="assetId"
      class="absolute inset-x-0 bottom-0 z-30 max-h-[50vh] overflow-hidden rounded-t-[1.6rem] border-t border-x border-white/10 bg-slate-900/95 shadow-2xl shadow-black/50 backdrop-blur-xl"
    >
      <!-- Header row 1: title + controls -->
      <div class="flex items-center justify-between gap-4 border-b border-white/10 px-5 py-3">
        <div class="min-w-0">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Open Vulnerabilities</p>
          <h4 class="mt-1 truncate text-base font-semibold text-white">{{ assetHost }}</h4>
        </div>
        <div class="flex items-center gap-3">
          <!-- Tag selector -->
          <select
            class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300 outline-none transition hover:border-white/20 cursor-pointer"
            :value="currentTag || ''"
            @change="(e) => { const v = (e.target as HTMLSelectElement).value; v ? emit('set-tag', v) : emit('remove-tag') }"
          >
            <option value="" class="bg-slate-900">No tag</option>
            <option value="investigating" class="bg-slate-900">🟡 Investigating</option>
            <option value="accepted_risk" class="bg-slate-900">⚪ Accepted Risk</option>
            <option value="resolved" class="bg-slate-900">🟢 Resolved</option>
          </select>
          <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
            {{ filtered.length }}<span v-if="searchQuery" class="text-slate-500">/{{ total }}</span><span v-else> finding{{ total !== 1 ? 's' : '' }}</span>
          </span>
          <button
            type="button"
            class="shrink-0 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="emit('close')"
          >
            Close
          </button>
        </div>
      </div>

      <!-- Header row 2: search bar -->
      <div class="border-b border-white/[0.06] px-5 py-2">
        <div class="relative">
          <svg xmlns="http://www.w3.org/2000/svg" class="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8" /><path stroke-linecap="round" d="m21 21-4.35-4.35" />
          </svg>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search vulnerabilities…"
            class="w-full rounded-xl border border-white/10 bg-white/[0.03] py-1.5 pl-9 pr-3 text-xs text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
          >
        </div>
      </div>

      <!-- Content -->
      <div class="max-h-[calc(50vh-8rem)] overflow-y-auto">
        <div v-if="loading" class="px-5 py-8 text-center text-sm text-slate-400">
          Loading vulnerabilities...
        </div>

        <div v-else-if="filtered.length === 0" class="px-5 py-8 text-center text-sm text-slate-400">
          {{ searchQuery ? 'No vulnerabilities match your search.' : 'No open vulnerabilities found for this asset.' }}
        </div>

        <table v-else class="min-w-full divide-y divide-white/6 text-sm">
          <thead>
            <tr class="text-left text-xs uppercase tracking-[0.24em] text-slate-500">
              <th class="px-4 py-2.5">Name</th>
              <th class="px-4 py-2.5">Severity</th>
              <th class="px-4 py-2.5">IP</th>
              <th class="px-4 py-2.5">Port</th>
              <th class="px-4 py-2.5">Source</th>
              <th class="px-4 py-2.5">Last Seen</th>
              <th class="px-4 py-2.5 text-center">Action</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr
              v-for="v in paginatedVulns"
              :key="v.id || v.fingerprint"
              class="cursor-pointer text-slate-200 transition hover:bg-white/[0.03]"
              @click="openVulnDetail(v)"
            >
              <td class="px-4 py-3">
                <p class="max-w-[22rem] truncate font-semibold text-white">{{ v.name || '--' }}</p>
              </td>
              <td class="px-4 py-3">
                <span class="inline-flex rounded-full px-3 py-0.5 text-xs font-semibold uppercase tracking-[0.2em]" :class="severityClasses(effectiveSeverity(v))">
                  {{ effectiveSeverity(v) }}
                </span>
              </td>
              <td class="px-4 py-3 text-slate-300">{{ v.ip || '--' }}</td>
              <td class="px-4 py-3 text-slate-300">{{ v.port || '--' }}</td>
              <td class="px-4 py-3 text-slate-300">{{ v.source_tool_first || '--' }}</td>
              <td class="px-4 py-3 text-slate-300">{{ formatDate(v.last_seen) }}</td>
              <td class="px-4 py-3 text-center">
                <button
                  type="button"
                  class="rounded-full border border-slate-500/25 bg-slate-500/10 px-2.5 py-1 text-[10px] font-semibold text-slate-300 transition hover:border-orange-400/30 hover:bg-orange-400/10 hover:text-orange-200 disabled:opacity-40"
                  :disabled="archivingId === (v.fingerprint || v.id)"
                  title="Archive — hide false positive / low priority"
                  @click.stop="archiveVuln(v)"
                >
                  {{ archivingId === (v.fingerprint || v.id) ? '...' : '📦 Archive' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Pagination -->
        <div
          v-if="totalPages > 1"
          class="flex items-center justify-center gap-1.5 border-t border-white/[0.06] px-4 py-2.5"
        >
          <button
            type="button"
            class="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1 text-xs text-slate-400 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-30"
            :disabled="currentPage <= 1"
            @click="currentPage--"
          >
            ‹ Prev
          </button>
          <template v-for="p in totalPages" :key="p">
            <button
              v-if="p <= 5 || p === totalPages || Math.abs(p - currentPage) <= 1"
              type="button"
              class="h-7 w-7 rounded-lg text-xs font-semibold transition"
              :class="p === currentPage ? 'border border-orange-400/30 bg-orange-400/15 text-orange-200' : 'text-slate-400 hover:bg-white/[0.06] hover:text-white'"
              @click="currentPage = p"
            >
              {{ p }}
            </button>
            <span
              v-else-if="(p === 2 && currentPage > 4) || (p === totalPages - 1 && currentPage < totalPages - 3)"
              class="text-xs text-slate-600"
            >…</span>
          </template>
          <button
            type="button"
            class="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1 text-xs text-slate-400 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-30"
            :disabled="currentPage >= totalPages"
            @click="currentPage++"
          >
            Next ›
          </button>
        </div>
      </div>

    </div>
  </Transition>

  <!-- Vuln detail modal — Teleported to body so it renders full-screen centered -->
  <Teleport to="body">
    <VulnerabilityDetailModal
      v-if="selectedVuln"
      :vulnerability="selectedVuln"
      :copied-section="copiedSection"
      @close="closeVulnDetail"
      @copy="(section, value) => copyContent(section, value)"
    />
  </Teleport>
</template>

<style scoped>
.slide-up-enter-active,
.slide-up-leave-active {
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease;
}
.slide-up-enter-from,
.slide-up-leave-to {
  transform: translateY(100%);
  opacity: 0;
}
</style>
