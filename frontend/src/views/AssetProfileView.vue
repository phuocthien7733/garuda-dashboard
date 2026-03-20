<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import AssetNetworkGraph from "@/components/assets/AssetNetworkGraph.vue";
import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";

type AssetDetailResponse = {
  asset: Record<string, unknown>;
};

type VulnerabilityRecord = {
  id?: string;
  fingerprint?: string;
  name?: string;
  severity?: string;
  override_severity?: string | null;
  ip?: string | null;
  host?: string | null;
  port?: string | number | null;
  status?: string | null;
  request?: string | null;
  response?: string | null;
  "curl-command"?: string | null;
  curl_command?: string | null;
  [key: string]: unknown;
};

type AssetVulnerabilitiesResponse = {
  asset_host: string;
  items: VulnerabilityRecord[];
  total: number;
};

type TriagePayload = {
  status?: string;
  override_severity?: string;
};

const PAGE_SIZE = 20;
const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low", "info"] as const;
const STATUS_OPTIONS = ["Open", "Investigating", "Accepted Risk", "Resolved"];
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const authStore = useAuthStore();
const route = useRoute();
const router = useRouter();

const asset = ref<Record<string, unknown> | null>(null);
const vulnerabilities = ref<VulnerabilityRecord[]>([]);
const totalVulnerabilities = ref(0);
const loading = ref(false);
const errorMessage = ref("");
const selectedVulnerability = ref<VulnerabilityRecord | null>(null);
const actionVulnerability = ref<VulnerabilityRecord | null>(null);
const copiedSection = ref<"request" | "response" | "curl" | null>(null);
const searchQuery = ref("");
const severityFilter = ref<(typeof SEVERITY_FILTERS)[number]>("all");
const portFilter = ref("all");
const currentPage = ref(1);
const selectedFingerprints = ref<string[]>([]);
const singleStatus = ref("");
const singleSeverity = ref("");
const bulkStatus = ref("");
const bulkSeverity = ref("");
const triageSubmitting = ref(false);
const bulkSubmitting = ref(false);

const assetId = computed(() => (typeof route.params.id === "string" ? route.params.id : ""));
const isValidAssetId = computed(() => /^[a-f\d]{24}$/i.test(assetId.value));
const pageTitle = computed(() => (asset.value?.host ? `Asset Profile: ${String(asset.value.host)}` : assetId.value ? "Asset Profile" : "Asset Detail"));
const pageDescription = computed(() =>
  assetId.value
    ? "Comprehensive asset intelligence for pentest preparation, PoC execution, and reporting."
    : "Select an asset from the dashboard or inventory to inspect its full technical context.",
);
const hostname = computed(() => String(asset.value?.host ?? assetId.value ?? "--"));
const assetIpAddresses = computed(() => {
  const value = asset.value?.ip_addresses;
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
});
const assetPorts = computed(() => {
  const value = asset.value?.open_ports;
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
});
const assetServices = computed(() => {
  const value = asset.value?.services;
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
});
const assetTemplateIds = computed(() => {
  const value = asset.value?.template_ids;
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
});
const highestSeverity = computed(() => String(asset.value?.highest_severity ?? "--"));
const isAdmin = computed(() => authStore.isAdmin);
const availablePorts = computed(() => {
  const ports = new Set<string>();
  for (const vulnerability of vulnerabilities.value) {
    const port = String(vulnerability.port ?? "").trim();
    if (port) {
      ports.add(port);
    }
  }
  return Array.from(ports).sort((left, right) => {
    const leftNumber = Number(left);
    const rightNumber = Number(right);
    if (Number.isNaN(leftNumber) || Number.isNaN(rightNumber)) {
      return left.localeCompare(right);
    }
    return leftNumber - rightNumber;
  });
});

const filteredVulnerabilities = computed(() => {
  const query = searchQuery.value.trim().toLowerCase();

  return [...vulnerabilities.value]
    .filter((vulnerability) => {
      const severity = effectiveSeverity(vulnerability).toLowerCase();
      const port = String(vulnerability.port ?? "").trim();

      if (severityFilter.value !== "all" && severity !== severityFilter.value) {
        return false;
      }

      if (portFilter.value !== "all" && port !== portFilter.value) {
        return false;
      }

      if (!query) {
        return true;
      }

      const haystack = [
        vulnerability.name,
        vulnerability.host,
        vulnerability.ip,
        vulnerability.port,
        vulnerability["template-id"],
        vulnerability["matcher-name"],
      ]
        .map((item) => String(item ?? "").toLowerCase())
        .join(" ");

      return haystack.includes(query);
    })
    .sort((left, right) => {
      const severityDelta = (severityRank[effectiveSeverity(right).toLowerCase()] ?? 0) - (severityRank[effectiveSeverity(left).toLowerCase()] ?? 0);
      if (severityDelta !== 0) {
        return severityDelta;
      }

      const leftLastSeen = parseDateValue(left.last_seen);
      const rightLastSeen = parseDateValue(right.last_seen);
      if (leftLastSeen !== rightLastSeen) {
        return rightLastSeen - leftLastSeen;
      }

      return String(left.name ?? "").localeCompare(String(right.name ?? ""));
    });
});

const totalFiltered = computed(() => filteredVulnerabilities.value.length);
const pageCount = computed(() => Math.max(1, Math.ceil(totalFiltered.value / PAGE_SIZE)));
const paginatedVulnerabilities = computed(() => {
  const startIndex = (currentPage.value - 1) * PAGE_SIZE;
  return filteredVulnerabilities.value.slice(startIndex, startIndex + PAGE_SIZE);
});
const selectedCount = computed(() => selectedFingerprints.value.length);
const selectablePageFingerprints = computed(() =>
  paginatedVulnerabilities.value
    .map((vulnerability) => rowFingerprint(vulnerability))
    .filter(Boolean),
);
const allPageRowsSelected = computed(() =>
  selectablePageFingerprints.value.length > 0 && selectablePageFingerprints.value.every((fingerprint) => selectedFingerprints.value.includes(fingerprint)),
);
const selectedVulnerabilityCurl = computed(() => extractCurlCommand(selectedVulnerability.value));

const vulnerabilityDetailEntries = computed(() => {
  if (!selectedVulnerability.value) {
    return [];
  }

  const excludedKeys = new Set([
    "id",
    "name",
    "severity",
    "override_severity",
    "ip",
    "host",
    "port",
    "status",
    "request",
    "response",
    "curl-command",
    "curl_command",
  ]);

  return Object.entries(selectedVulnerability.value)
    .filter(([key, value]) => !excludedKeys.has(key) && value !== null && value !== undefined && value !== "")
    .map(([key, value]) => ({
      key,
      label: key.replace(/_/g, " ").replace(/-/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()),
      value: formatDisplayValue(key, value),
    }));
});

function parseDateValue(value: unknown) {
  if (!value) {
    return 0;
  }

  const timestamp = new Date(String(value)).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function formatDate(value: unknown) {
  if (!value) {
    return "--";
  }

  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  const pad = (item: number) => String(item).padStart(2, "0");
  return `${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${date.getFullYear()} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function isDateLikeField(key: string, value: unknown) {
  if (typeof value !== "string" && !(value instanceof Date)) {
    return false;
  }

  return /(time|seen|date|timestamp|matched)/i.test(key) || /^\d{4}-\d{2}-\d{2}T/.test(String(value));
}

function formatDisplayValue(key: string, value: unknown) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(", ");
  }

  if (isDateLikeField(key, value)) {
    return formatDate(value);
  }

  if (value && typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  if (value === null || value === undefined || value === "") {
    return "--";
  }

  return String(value);
}

function severityClasses(value: unknown) {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized === "critical") {
    return "border border-[#ff0308]/35 bg-[#ff0308]/10 text-[#ff8083]";
  }
  if (normalized === "high") {
    return "border border-[#f36d14]/35 bg-[#f36d14]/10 text-[#f8a15e]";
  }
  if (normalized === "medium") {
    return "border border-[#ffe240]/35 bg-[#ffe240]/10 text-[#ffe97a]";
  }
  if (normalized === "low") {
    return "border border-[#389e0d]/35 bg-[#389e0d]/10 text-[#8fd46d]";
  }
  if (normalized === "info") {
    return "border border-[#096dd9]/35 bg-[#096dd9]/10 text-[#68b0ff]";
  }
  return "border border-white/10 bg-white/[0.04] text-slate-300";
}

function effectiveSeverity(vulnerability: VulnerabilityRecord) {
  return String(vulnerability.override_severity || vulnerability.severity || "unknown");
}

function effectiveStatus(vulnerability: VulnerabilityRecord) {
  return String(vulnerability.status || "Open");
}

function rowFingerprint(vulnerability: VulnerabilityRecord) {
  return String(vulnerability.fingerprint ?? "");
}

function extractCurlCommand(vulnerability: VulnerabilityRecord | null) {
  if (!vulnerability) {
    return "";
  }
  return String(vulnerability["curl-command"] || vulnerability.curl_command || "");
}

function resetActionInputs() {
  singleStatus.value = "";
  singleSeverity.value = "";
}

async function fetchAssetData() {
  if (!assetId.value) {
    asset.value = null;
    vulnerabilities.value = [];
    totalVulnerabilities.value = 0;
    errorMessage.value = "";
    return;
  }

  if (!isValidAssetId.value) {
    asset.value = null;
    vulnerabilities.value = [];
    totalVulnerabilities.value = 0;
    errorMessage.value = "Invalid asset identifier.";
    selectedVulnerability.value = null;
    return;
  }

  loading.value = true;
  errorMessage.value = "";
  selectedVulnerability.value = null;
  actionVulnerability.value = null;
  selectedFingerprints.value = [];

  try {
    const [{ data: assetData }, { data: vulnerabilityData }] = await Promise.all([
      api.get<AssetDetailResponse>(`/api/assets/${encodeURIComponent(assetId.value)}/detail`),
      api.get<AssetVulnerabilitiesResponse>(`/api/assets/${encodeURIComponent(assetId.value)}/vulnerabilities`),
    ]);

    asset.value = assetData.asset;
    vulnerabilities.value = vulnerabilityData.items ?? [];
    totalVulnerabilities.value = vulnerabilityData.total ?? vulnerabilities.value.length;
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail || "Unable to load this asset.";
    asset.value = null;
    vulnerabilities.value = [];
    totalVulnerabilities.value = 0;
  } finally {
    loading.value = false;
  }
}

function goBackToInventory() {
  void router.push({ name: "assets" });
}

function openVulnerabilityDetail(vulnerability: VulnerabilityRecord) {
  selectedVulnerability.value = vulnerability;
  copiedSection.value = null;
}

function closeVulnerabilityDetail() {
  selectedVulnerability.value = null;
  copiedSection.value = null;
}

function openActionModal(vulnerability: VulnerabilityRecord) {
  if (!isAdmin.value || !rowFingerprint(vulnerability)) {
    return;
  }
  actionVulnerability.value = vulnerability;
  resetActionInputs();
}

function closeActionModal() {
  actionVulnerability.value = null;
  resetActionInputs();
}

async function copyContent(section: "request" | "response" | "curl", value: unknown) {
  const text = String(value ?? "");
  if (!text || text === "--") {
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    copiedSection.value = section;
    window.setTimeout(() => {
      if (copiedSection.value === section) {
        copiedSection.value = null;
      }
    }, 1800);
  } catch (error) {
    console.error(error);
  }
}

function toggleVulnerabilitySelection(vulnerability: VulnerabilityRecord) {
  const fingerprint = rowFingerprint(vulnerability);
  if (!fingerprint || !isAdmin.value) {
    return;
  }

  if (selectedFingerprints.value.includes(fingerprint)) {
    selectedFingerprints.value = selectedFingerprints.value.filter((item) => item !== fingerprint);
    return;
  }

  selectedFingerprints.value = [...selectedFingerprints.value, fingerprint];
}

function toggleAllCurrentPage() {
  if (!isAdmin.value) {
    return;
  }

  if (allPageRowsSelected.value) {
    selectedFingerprints.value = selectedFingerprints.value.filter(
      (fingerprint) => !selectablePageFingerprints.value.includes(fingerprint),
    );
    return;
  }

  selectedFingerprints.value = Array.from(new Set([...selectedFingerprints.value, ...selectablePageFingerprints.value]));
}

function isRowSelected(vulnerability: VulnerabilityRecord) {
  const fingerprint = rowFingerprint(vulnerability);
  return fingerprint ? selectedFingerprints.value.includes(fingerprint) : false;
}

function buildTriagePayload(statusValue: string, severityValue: string) {
  const payload: TriagePayload = {};
  if (statusValue) {
    payload.status = statusValue;
  }
  if (severityValue) {
    payload.override_severity = severityValue;
  }
  return payload;
}

async function applySingleAction() {
  if (!actionVulnerability.value) {
    return;
  }

  const fingerprint = rowFingerprint(actionVulnerability.value);
  if (!fingerprint) {
    return;
  }

  const payload = buildTriagePayload(singleStatus.value, singleSeverity.value);
  if (!payload.status && !payload.override_severity) {
    return;
  }

  triageSubmitting.value = true;
  try {
    await api.patch(`/api/vulns/${encodeURIComponent(fingerprint)}`, payload);
    closeActionModal();
    await fetchAssetData();
  } catch (error) {
    console.error(error);
  } finally {
    triageSubmitting.value = false;
  }
}

async function applyBulkAction() {
  const fingerprints = [...selectedFingerprints.value];
  if (!isAdmin.value || fingerprints.length === 0) {
    return;
  }

  const payload = {
    fingerprints,
    ...buildTriagePayload(bulkStatus.value, bulkSeverity.value),
  };

  if (!("status" in payload) && !("override_severity" in payload)) {
    return;
  }

  bulkSubmitting.value = true;
  try {
    await api.post("/api/vulns/bulk-triage", payload);
    selectedFingerprints.value = [];
    bulkStatus.value = "";
    bulkSeverity.value = "";
    await fetchAssetData();
  } catch (error) {
    console.error(error);
  } finally {
    bulkSubmitting.value = false;
  }
}

function goToPreviousPage() {
  currentPage.value = Math.max(1, currentPage.value - 1);
}

function goToNextPage() {
  currentPage.value = Math.min(pageCount.value, currentPage.value + 1);
}

function handleEscape(event: KeyboardEvent) {
  if (event.key === "Escape") {
    if (actionVulnerability.value) {
      closeActionModal();
      return;
    }

    if (selectedVulnerability.value) {
      closeVulnerabilityDetail();
    }
  }
}

watch(
  () => route.fullPath,
  () => {
    void fetchAssetData();
  },
);

watch([searchQuery, severityFilter, portFilter], () => {
  currentPage.value = 1;
});

watch(pageCount, (value) => {
  if (currentPage.value > value) {
    currentPage.value = value;
  }
});

onMounted(() => {
  void fetchAssetData();
  window.addEventListener("keydown", handleEscape);
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", handleEscape);
});
</script>

<template>
  <AppShell eyebrow="T&W Falcon" :title="pageTitle" :description="pageDescription">
    <template #header-actions>
      <button
        v-if="assetId"
        type="button"
        class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
        @click="goBackToInventory"
      >
        Back to inventory
      </button>
      <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-slate-300">
        {{ authStore.username }}
      </span>
      <span class="rounded-full border border-orange-400/30 bg-orange-400/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-orange-200">
        {{ authStore.role }}
      </span>
    </template>

    <section v-if="!assetId" class="mt-4 rounded-[1.6rem] border border-dashed border-white/10 bg-slate-900/55 px-6 py-12 text-center text-sm text-slate-400">
      Select an asset from the dashboard or inventory to open the full asset profile.
    </section>

    <template v-else>
      <section class="mt-4 rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur-xl">
        <div class="flex items-center justify-between gap-4">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Asset Summary</p>
            <h3 class="mt-2 text-xl font-semibold text-white">{{ hostname }}</h3>
            <p class="mt-1 text-sm text-slate-400">
              High-signal technical context to support enumeration, PoC preparation, and reporting.
            </p>
          </div>
          <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em]" :class="severityClasses(highestSeverity)">
            {{ highestSeverity }}
          </span>
        </div>

        <div v-if="loading" class="mt-6 rounded-[1.25rem] border border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
          Loading asset intelligence...
        </div>

        <div v-else-if="errorMessage" class="mt-6 rounded-[1.25rem] border border-red-400/15 bg-red-500/5 px-5 py-10 text-center text-sm text-red-200">
          {{ errorMessage }}
        </div>

        <div v-else class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">IP</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <span
                v-for="ip in assetIpAddresses"
                :key="ip"
                class="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-200"
              >
                {{ ip }}
              </span>
              <span v-if="assetIpAddresses.length === 0" class="text-sm text-slate-400">--</span>
            </div>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">Hostname</p>
            <p class="mt-3 text-sm font-semibold text-white">{{ hostname }}</p>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">Port</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <span
                v-for="port in assetPorts"
                :key="port"
                class="rounded-full border border-sky-400/20 bg-sky-400/10 px-2.5 py-1 text-xs text-sky-200"
              >
                {{ port }}
              </span>
              <span v-if="assetPorts.length === 0" class="text-sm text-slate-400">--</span>
            </div>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">First Seen</p>
            <p class="mt-3 text-sm text-slate-200">{{ formatDate(asset?.first_seen) }}</p>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">Last Seen</p>
            <p class="mt-3 text-sm text-slate-200">{{ formatDate(asset?.last_seen) }}</p>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">Access Type</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <span
                v-for="service in assetServices"
                :key="service"
                class="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-xs text-emerald-200"
              >
                {{ service }}
              </span>
              <span v-if="assetServices.length === 0" class="text-sm text-slate-400">--</span>
            </div>
          </article>

          <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4 md:col-span-2 xl:col-span-3">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-500">Template Id</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <span
                v-for="templateId in assetTemplateIds"
                :key="templateId"
                class="rounded-full border border-fuchsia-400/20 bg-fuchsia-400/10 px-2.5 py-1 text-xs text-fuchsia-200"
              >
                {{ templateId }}
              </span>
              <span v-if="assetTemplateIds.length === 0" class="text-sm text-slate-400">--</span>
            </div>
          </article>
        </div>
      </section>

      <AssetNetworkGraph :asset-id="assetId" />

      <section class="mt-4 rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur-xl">
        <div class="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Vulnerabilities</p>
            <h3 class="mt-2 text-xl font-semibold text-white">Asset Vulnerability Inventory</h3>
            <p class="mt-1 text-sm text-slate-400">
              Filter, inspect, and triage findings linked to this asset for PoC validation and reporting.
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
              Total: {{ totalVulnerabilities }}
            </span>
            <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
              Filtered: {{ totalFiltered }}
            </span>
            <span v-if="!isAdmin" class="rounded-full border border-sky-400/20 bg-sky-400/10 px-3 py-1.5 text-xs font-semibold text-sky-200">
              Read-only session
            </span>
          </div>
        </div>

        <div class="mt-6 grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)_minmax(0,0.8fr)]">
          <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
            Search
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Name, host, IP, template-id"
              class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
            >
          </label>

          <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
            Severity
            <select v-model="severityFilter" class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium uppercase tracking-normal text-white outline-none transition focus:border-orange-400/35">
              <option v-for="item in SEVERITY_FILTERS" :key="item" :value="item" class="bg-slate-950">
                {{ item === 'all' ? 'All Severities' : item }}
              </option>
            </select>
          </label>

          <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
            Port
            <select v-model="portFilter" class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition focus:border-orange-400/35">
              <option value="all" class="bg-slate-950">All Ports</option>
              <option v-for="port in availablePorts" :key="port" :value="port" class="bg-slate-950">
                {{ port }}
              </option>
            </select>
          </label>
        </div>

        <div class="mt-4 rounded-[1.25rem] border border-white/10 bg-slate-950/45 p-4">
          <div class="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div class="flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>Sorted by severity: Critical, High, Medium, Low, Info</span>
              <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
                Page {{ currentPage }} / {{ pageCount }}
              </span>
            </div>

            <div v-if="isAdmin" class="flex flex-wrap items-center gap-2">
              <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Bulk Action</span>
              <select v-model="bulkStatus" class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold text-white outline-none">
                <option value="" class="bg-slate-950">Status unchanged</option>
                <option v-for="status in STATUS_OPTIONS" :key="status" :value="status" class="bg-slate-950">
                  {{ status }}
                </option>
              </select>
              <select v-model="bulkSeverity" class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold uppercase text-white outline-none">
                <option value="" class="bg-slate-950">Severity unchanged</option>
                <option v-for="severity in SEVERITY_OPTIONS" :key="severity" :value="severity" class="bg-slate-950">
                  {{ severity }}
                </option>
              </select>
              <button
                type="button"
                class="rounded-full border border-orange-400/20 bg-orange-400/10 px-4 py-2 text-xs font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
                :disabled="selectedCount === 0 || bulkSubmitting || (!bulkStatus && !bulkSeverity)"
                @click="applyBulkAction"
              >
                {{ bulkSubmitting ? 'Applying...' : `Apply to ${selectedCount} selected` }}
              </button>
            </div>
          </div>
        </div>

        <div v-if="!loading && paginatedVulnerabilities.length === 0" class="mt-6 rounded-[1.25rem] border border-dashed border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
          No vulnerabilities match the current filters.
        </div>

        <div v-else-if="paginatedVulnerabilities.length > 0" class="mt-6 overflow-x-auto">
          <table class="min-w-full divide-y divide-white/8 text-sm">
            <thead>
              <tr class="text-left text-xs uppercase tracking-[0.24em] text-slate-500">
                <th v-if="isAdmin" class="px-3 py-3">
                  <input
                    type="checkbox"
                    class="h-4 w-4 rounded border-white/15 bg-white/[0.04] text-orange-400 focus:ring-orange-400"
                    :checked="allPageRowsSelected"
                    @click.stop
                    @change="toggleAllCurrentPage"
                  >
                </th>
                <th class="px-3 py-3">Name</th>
                <th class="px-3 py-3">Severity</th>
                <th class="px-3 py-3">IP</th>
                <th class="px-3 py-3">Host</th>
                <th class="px-3 py-3">Port</th>
                <th class="px-3 py-3">Status</th>
                <th class="px-3 py-3 text-right">Controls</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/6">
              <tr
                v-for="vulnerability in paginatedVulnerabilities"
                :key="vulnerability.fingerprint || vulnerability.id || `${vulnerability.name}-${vulnerability.host}`"
                class="cursor-pointer align-top text-slate-200 transition hover:bg-white/[0.03]"
                :class="isRowSelected(vulnerability) ? 'bg-orange-400/[0.05]' : ''"
                @click="openVulnerabilityDetail(vulnerability)"
              >
                <td v-if="isAdmin" class="px-3 py-4" @click.stop>
                  <input
                    type="checkbox"
                    class="h-4 w-4 rounded border-white/15 bg-white/[0.04] text-orange-400 focus:ring-orange-400"
                    :checked="isRowSelected(vulnerability)"
                    :disabled="!rowFingerprint(vulnerability)"
                    @change="toggleVulnerabilitySelection(vulnerability)"
                  >
                </td>
                <td class="px-3 py-4">
                  <div class="max-w-[22rem]">
                    <p class="font-semibold text-white">{{ vulnerability.name || '--' }}</p>
                  </div>
                </td>
                <td class="px-3 py-4">
                  <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em]" :class="severityClasses(effectiveSeverity(vulnerability))">
                    {{ effectiveSeverity(vulnerability) }}
                  </span>
                </td>
                <td class="px-3 py-4 text-slate-300">{{ vulnerability.ip || '--' }}</td>
                <td class="px-3 py-4 text-slate-300">{{ vulnerability.host || '--' }}</td>
                <td class="px-3 py-4 text-slate-300">{{ vulnerability.port || '--' }}</td>
                <td class="px-3 py-4">
                  <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
                    {{ effectiveStatus(vulnerability) }}
                  </span>
                </td>
                <td class="px-3 py-4 text-right" @click.stop>
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-100 transition hover:border-white/20 hover:bg-white/[0.08]"
                      @click="openVulnerabilityDetail(vulnerability)"
                    >
                      View detail
                    </button>
                    <button
                      v-if="isAdmin"
                      type="button"
                      class="rounded-full border border-orange-400/20 bg-orange-400/10 px-3 py-1.5 text-xs font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="!rowFingerprint(vulnerability)"
                      @click="openActionModal(vulnerability)"
                    >
                      Action
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="paginatedVulnerabilities.length > 0" class="mt-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <p class="text-sm text-slate-400">
            Showing {{ (currentPage - 1) * PAGE_SIZE + 1 }} - {{ Math.min(currentPage * PAGE_SIZE, totalFiltered) }} of {{ totalFiltered }} vulnerabilities.
          </p>
          <div class="flex items-center gap-2">
            <button
              type="button"
              class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-50"
              :disabled="currentPage === 1"
              @click="goToPreviousPage"
            >
              Previous
            </button>
            <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
              {{ currentPage }} / {{ pageCount }}
            </span>
            <button
              type="button"
              class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-50"
              :disabled="currentPage === pageCount"
              @click="goToNextPage"
            >
              Next
            </button>
          </div>
        </div>
      </section>
    </template>

    <div
      v-if="selectedVulnerability"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/78 px-4 py-6 backdrop-blur-sm"
      @click.self="closeVulnerabilityDetail"
    >
      <div class="max-h-[94vh] w-full max-w-[min(96vw,108rem)] overflow-hidden rounded-[1.6rem] border border-white/10 bg-slate-900 shadow-2xl shadow-black/40">
        <div class="flex items-start justify-between gap-4 border-b border-white/10 px-6 py-5">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Vulnerability Detail</p>
            <h3 class="mt-2 text-xl font-semibold text-white">{{ selectedVulnerability.name || 'Unnamed finding' }}</h3>
            <div class="mt-3 flex flex-wrap items-center gap-2">
              <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em]" :class="severityClasses(effectiveSeverity(selectedVulnerability))">
                {{ effectiveSeverity(selectedVulnerability) }}
              </span>
              <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
                {{ effectiveStatus(selectedVulnerability) }}
              </span>
              <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-400">
                {{ selectedVulnerability.host || '--' }}
              </span>
            </div>
          </div>

          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="closeVulnerabilityDetail"
          >
            Close
          </button>
        </div>

        <div class="max-h-[calc(94vh-5.5rem)] overflow-y-auto px-6 py-5">
          <section class="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
            <div class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
              <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Metadata</p>
              <div class="mt-4 grid gap-3 sm:grid-cols-2">
                <article
                  v-for="entry in vulnerabilityDetailEntries"
                  :key="entry.key"
                  class="rounded-xl border border-white/8 bg-white/[0.03] px-3 py-3"
                >
                  <p class="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{{ entry.label }}</p>
                  <pre class="mt-2 whitespace-pre-wrap break-words font-sans text-sm text-slate-200">{{ entry.value }}</pre>
                </article>
              </div>
            </div>

            <div class="space-y-4">
              <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
                <div class="flex items-center justify-between gap-3">
                  <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Curl Command</p>
                  <button
                    type="button"
                    class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
                    @click="copyContent('curl', selectedVulnerabilityCurl)"
                  >
                    {{ copiedSection === 'curl' ? 'Copied' : 'Copy curl' }}
                  </button>
                </div>
                <pre
                  class="mt-4 max-h-[12rem] overflow-auto rounded-[1rem] border border-white/8 bg-slate-950 px-4 py-4 text-xs leading-6 text-slate-200"
                  @click="copyContent('curl', selectedVulnerabilityCurl)"
                >{{ selectedVulnerabilityCurl || 'No curl command available.' }}</pre>
              </article>

              <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
                <div class="flex items-center justify-between gap-3">
                  <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">PoC Request</p>
                  <button
                    type="button"
                    class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
                    @click="copyContent('request', selectedVulnerability.request)"
                  >
                    {{ copiedSection === 'request' ? 'Copied' : 'Copy request' }}
                  </button>
                </div>
                <pre
                  class="mt-4 max-h-[16rem] overflow-auto rounded-[1rem] border border-white/8 bg-slate-950 px-4 py-4 text-xs leading-6 text-slate-200"
                  @click="copyContent('request', selectedVulnerability.request)"
                >{{ selectedVulnerability.request || 'No request data available.' }}</pre>
              </article>

              <article class="rounded-[1.25rem] border border-white/10 bg-slate-950/55 p-4">
                <div class="flex items-center justify-between gap-3">
                  <p class="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">PoC Response</p>
                  <button
                    type="button"
                    class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
                    @click="copyContent('response', selectedVulnerability.response)"
                  >
                    {{ copiedSection === 'response' ? 'Copied' : 'Copy response' }}
                  </button>
                </div>
                <pre
                  class="mt-4 max-h-[16rem] overflow-auto rounded-[1rem] border border-white/8 bg-slate-950 px-4 py-4 text-xs leading-6 text-slate-200"
                  @click="copyContent('response', selectedVulnerability.response)"
                >{{ selectedVulnerability.response || 'No response data available.' }}</pre>
              </article>
            </div>
          </section>
        </div>
      </div>
    </div>

    <div
      v-if="actionVulnerability"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/78 px-4 py-6 backdrop-blur-sm"
      @click.self="closeActionModal"
    >
      <div class="w-full max-w-2xl rounded-[1.6rem] border border-white/10 bg-slate-900 shadow-2xl shadow-black/40">
        <div class="border-b border-white/10 px-6 py-5">
          <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Triage Action</p>
          <h3 class="mt-2 text-xl font-semibold text-white">{{ actionVulnerability.name || 'Unnamed finding' }}</h3>
          <p class="mt-2 text-sm text-slate-400">
            Update the status or override severity for this vulnerability.
          </p>
        </div>

        <div class="space-y-4 px-6 py-5">
          <div class="grid gap-4 md:grid-cols-2">
            <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
              New Status
              <select v-model="singleStatus" class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none">
                <option value="" class="bg-slate-950">Leave unchanged</option>
                <option v-for="status in STATUS_OPTIONS" :key="status" :value="status" class="bg-slate-950">
                  {{ status }}
                </option>
              </select>
            </label>

            <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
              Override Severity
              <select v-model="singleSeverity" class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium uppercase tracking-normal text-white outline-none">
                <option value="" class="bg-slate-950">Leave unchanged</option>
                <option v-for="severity in SEVERITY_OPTIONS" :key="severity" :value="severity" class="bg-slate-950">
                  {{ severity }}
                </option>
              </select>
            </label>
          </div>

          <div class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-sm text-slate-400">
            Current status: <span class="font-semibold text-slate-200">{{ effectiveStatus(actionVulnerability) }}</span>
            <span class="mx-2 text-slate-600">|</span>
            Current severity: <span class="font-semibold text-slate-200">{{ effectiveSeverity(actionVulnerability) }}</span>
          </div>
        </div>

        <div class="flex items-center justify-end gap-3 border-t border-white/10 px-6 py-4">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="closeActionModal"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-full border border-orange-400/20 bg-orange-400/10 px-4 py-2 text-xs font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="triageSubmitting || (!singleStatus && !singleSeverity)"
            @click="applySingleAction"
          >
            {{ triageSubmitting ? 'Applying...' : 'Apply action' }}
          </button>
        </div>
      </div>
    </div>
  </AppShell>
</template>
