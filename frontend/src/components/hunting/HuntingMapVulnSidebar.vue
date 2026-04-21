<script setup lang="ts">
import { ref, watch } from "vue";

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

const props = defineProps<{
  mapId: string;
  assetId: string | null;
  assetHost: string;
}>();

const emit = defineEmits<{
  close: [];
}>();

const vulnerabilities = ref<VulnerabilityRecord[]>([]);
const total = ref(0);
const loading = ref(false);
const selectedVuln = ref<VulnerabilityRecord | null>(null);
const copiedSection = ref<"request" | "response" | "curl" | null>(null);

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
      <!-- Header -->
      <div class="flex items-center justify-between gap-4 border-b border-white/10 px-5 py-3">
        <div class="min-w-0">
          <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Open Vulnerabilities</p>
          <h4 class="mt-1 truncate text-base font-semibold text-white">{{ assetHost }}</h4>
        </div>
        <div class="flex items-center gap-3">
          <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
            {{ total }} finding{{ total !== 1 ? 's' : '' }}
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

      <!-- Content -->
      <div class="max-h-[calc(50vh-4rem)] overflow-y-auto">
        <div v-if="loading" class="px-5 py-8 text-center text-sm text-slate-400">
          Loading vulnerabilities...
        </div>

        <div v-else-if="vulnerabilities.length === 0" class="px-5 py-8 text-center text-sm text-slate-400">
          No open vulnerabilities found for this asset.
        </div>

        <table v-else class="min-w-full divide-y divide-white/6 text-sm">
          <thead>
            <tr class="text-left text-xs uppercase tracking-[0.24em] text-slate-500">
              <th class="px-4 py-2.5">Name</th>
              <th class="px-4 py-2.5">Severity</th>
              <th class="px-4 py-2.5">IP</th>
              <th class="px-4 py-2.5">Port</th>
              <th class="px-4 py-2.5">Source Tool</th>
              <th class="px-4 py-2.5">Last Seen</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr
              v-for="v in vulnerabilities"
              :key="v.id || v.fingerprint"
              class="cursor-pointer text-slate-200 transition hover:bg-white/[0.03]"
              @click="openVulnDetail(v)"
            >
              <td class="px-4 py-3">
                <p class="max-w-[24rem] truncate font-semibold text-white">{{ v.name || '--' }}</p>
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
            </tr>
          </tbody>
        </table>
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
