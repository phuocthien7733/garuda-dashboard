<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppShell from "@/components/layout/AppShell.vue";
import DatePickerField from "@/components/shared/DatePickerField.vue";
import api from "@/services/api";

type AssetRecord = {
  id: string;
  host: string;
  ip_addresses: string[];
  open_ports: string[];
  highest_severity?: string | null;
  vulnerability_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
};

type AssetListResponse = {
  items: AssetRecord[];
  total: number;
  next_cursor?: string | null;
  page_size?: number;
};

type DashboardStats = {
  assets: number;
  open_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
};

const PAGE_SIZE_OPTIONS = [20, 50, 100] as const;
const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low", "info"] as const;
const TIME_FIELD_OPTIONS = [
  { value: "last_seen", label: "Last Seen" },
  { value: "first_seen", label: "First Seen" },
] as const;

const router = useRouter();
const route = useRoute();

const loading = ref(false);
const errorMessage = ref("");
const assets = ref<AssetRecord[]>([]);
const searchQuery = ref("");
const debouncedSearchQuery = ref("");
const severityFilter = ref<(typeof SEVERITY_FILTERS)[number]>("all");
const portFilter = ref("all");
const timeField = ref<(typeof TIME_FIELD_OPTIONS)[number]["value"]>("last_seen");
const dateFrom = ref("");
const dateTo = ref("");
const currentPage = ref(1);
const pageSize = ref<(typeof PAGE_SIZE_OPTIONS)[number]>(20);
const currentCursor = ref<string | null>(null);
const nextCursor = ref<string | null>(null);
const cursorHistory = ref<Array<string | null>>([]);
let searchDebounceTimer: number | undefined;
const stats = ref<DashboardStats>({
  assets: 0,
  open_vulnerabilities: 0,
  critical_vulnerabilities: 0,
  high_vulnerabilities: 0,
  medium_vulnerabilities: 0,
});

const statCards = computed(() => [
  {
    key: "assets",
    label: "Assets",
    value: stats.value.assets,
    classes: "border-white/10 bg-white/[0.04] text-white",
  },
  {
    key: "open",
    label: "Open Vulns",
    value: stats.value.open_vulnerabilities,
    classes: "border-[#ff0308]/25 bg-gradient-to-r from-[#ff0308]/12 via-[#f36d14]/12 to-[#ff0308]/8 text-[#ffd0d1]",
  },
  {
    key: "critical",
    label: "Critical",
    value: stats.value.critical_vulnerabilities,
    classes: "border-[#ff0308]/25 bg-[#ff0308]/10 text-[#ff8a8d]",
  },
  {
    key: "high",
    label: "High",
    value: stats.value.high_vulnerabilities,
    classes: "border-[#f36d14]/25 bg-[#f36d14]/10 text-[#ffb380]",
  },
  {
    key: "medium",
    label: "Medium",
    value: stats.value.medium_vulnerabilities,
    classes: "border-[#ffe240]/25 bg-[#ffe240]/10 text-[#fff09a]",
  },
]);

const availablePorts = computed(() => {
  const ports = new Set<string>();
  for (const asset of assets.value) {
    for (const port of asset.open_ports ?? []) {
      const normalized = String(port ?? "").trim();
      if (normalized) {
        ports.add(normalized);
      }
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

const totalAssets = ref(0);
const totalFiltered = computed(() => totalAssets.value);
const pageCount = computed(() => Math.max(1, Math.ceil(totalFiltered.value / pageSize.value)));
const paginatedAssets = computed(() => assets.value);

function hydrateFiltersFromRouteQuery() {
  const search = String(route.query.search ?? "").trim();
  if (search) {
    searchQuery.value = search;
    debouncedSearchQuery.value = search;
  }
}

async function fetchAssetInventory() {
  loading.value = true;
  errorMessage.value = "";

  try {
    const [{ data: statsData }, { data: assetData }] = await Promise.all([
      api.get<DashboardStats>("/stats"),
      api.get<AssetListResponse>("/assets", {
        params: {
          page_size: pageSize.value,
          cursor: currentCursor.value || undefined,
          search: debouncedSearchQuery.value.trim() || undefined,
          severity: severityFilter.value !== "all" ? severityFilter.value : undefined,
          port: portFilter.value !== "all" ? portFilter.value : undefined,
          time_field: timeField.value,
          date_from: dateFrom.value || undefined,
          date_to: dateTo.value || undefined,
        },
      }),
    ]);

    stats.value = {
      assets: Number(statsData.assets ?? 0),
      open_vulnerabilities: Number(statsData.open_vulnerabilities ?? 0),
      critical_vulnerabilities: Number(statsData.critical_vulnerabilities ?? 0),
      high_vulnerabilities: Number(statsData.high_vulnerabilities ?? 0),
      medium_vulnerabilities: Number(statsData.medium_vulnerabilities ?? 0),
    };
    assets.value = assetData.items ?? [];
    totalAssets.value = Number(assetData.total ?? 0);
    nextCursor.value = assetData.next_cursor ?? null;
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail || "Unable to load asset inventory.";
    assets.value = [];
    totalAssets.value = 0;
    nextCursor.value = null;
  } finally {
    loading.value = false;
  }
}

async function openAssetDetail(asset: AssetRecord) {
  await router.push({ name: "asset-profile", params: { id: asset.id } });
}

function goToPreviousPage() {
  if (currentPage.value <= 1 || cursorHistory.value.length === 0) {
    return;
  }
  const previousCursor = cursorHistory.value.pop() ?? null;
  currentCursor.value = previousCursor;
  currentPage.value = Math.max(1, currentPage.value - 1);
  void fetchAssetInventory();
}

function goToNextPage() {
  if (!nextCursor.value || currentPage.value >= pageCount.value) {
    return;
  }
  cursorHistory.value.push(currentCursor.value);
  currentCursor.value = nextCursor.value;
  currentPage.value = Math.min(pageCount.value, currentPage.value + 1);
  void fetchAssetInventory();
}

watch(searchQuery, (value) => {
  if (searchDebounceTimer) {
    window.clearTimeout(searchDebounceTimer);
  }
  searchDebounceTimer = window.setTimeout(() => {
    debouncedSearchQuery.value = value;
  }, 300);
});

watch([debouncedSearchQuery, severityFilter, portFilter, timeField, dateFrom, dateTo, pageSize], () => {
  currentCursor.value = null;
  nextCursor.value = null;
  cursorHistory.value = [];
  currentPage.value = 1;
  void fetchAssetInventory();
});

watch(pageCount, (value) => {
  if (currentPage.value > value) {
    currentPage.value = value;
  }
});

onMounted(() => {
  hydrateFiltersFromRouteQuery();
  debouncedSearchQuery.value = searchQuery.value;
  void fetchAssetInventory();
});

onBeforeUnmount(() => {
  if (searchDebounceTimer) {
    window.clearTimeout(searchDebounceTimer);
  }
});
</script>

<template>
  <AppShell
    eyebrow="T&W Falcon"
    title="Asset Inventory"
    description="Complete visibility across internet-facing assets with quick access to exposure details and host-level context."
  >
    <section class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
      <article
        v-for="item in statCards"
        :key="item.key"
        class="rounded-[1.35rem] border p-4 backdrop-blur-xl"
        :class="item.classes"
      >
        <p class="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-300/80">{{ item.label }}</p>
        <p class="mt-3 text-3xl font-black text-white">{{ item.value }}</p>
      </article>
    </section>

    <section class="mt-4 rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur-xl">
      <div class="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Assets</p>
          <h3 class="mt-2 text-xl font-semibold text-white">Internet-Facing Asset Inventory</h3>
          <p class="mt-1 text-sm text-slate-400">
            Review every host, its exposed infrastructure, and the total vulnerability load before pivoting into asset detail.
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-2 xl:justify-end">
          <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
            Total: {{ stats.assets }}
          </span>
          <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
            Filtered: {{ totalFiltered }}
          </span>
        </div>
      </div>

      <div v-if="loading" class="mt-6 rounded-[1.25rem] border border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
        Loading asset inventory...
      </div>

      <div v-else-if="errorMessage" class="mt-6 rounded-[1.25rem] border border-red-400/15 bg-red-500/5 px-5 py-10 text-center text-sm text-red-200">
        {{ errorMessage }}
      </div>

      <div v-else-if="assets.length === 0" class="mt-6 rounded-[1.25rem] border border-dashed border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
        No assets available in the inventory.
      </div>

      <div v-else class="mt-6">
        <div class="space-y-3">
          <div class="grid gap-3 xl:grid-cols-4">
            <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400 xl:col-span-2">
              Search
              <input
                v-model="searchQuery"
                type="text"
                placeholder="Host or IP address"
                class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
              >
            </label>

            <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
              Highest Severity
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

          <div class="grid gap-3 xl:grid-cols-3">
            <div class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400 xl:col-span-2">
              Date Range
              <div class="mt-1 text-[11px] normal-case tracking-normal text-slate-500">
                Filter assets by first seen or last seen date.
              </div>
              <div class="mt-2 grid gap-3 sm:grid-cols-2">
                <DatePickerField v-model="dateFrom" label="From" />
                <DatePickerField v-model="dateTo" label="To" />
              </div>
            </div>

            <label class="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
              Filter By
              <div class="mt-1 text-[11px] normal-case tracking-normal text-slate-500">
                Choose which timeline the date range should apply to.
              </div>
              <select v-model="timeField" class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition focus:border-orange-400/35">
                <option v-for="option in TIME_FIELD_OPTIONS" :key="option.value" :value="option.value" class="bg-slate-950">
                  {{ option.label }}
                </option>
              </select>
            </label>
          </div>
        </div>

        <div class="mt-4 rounded-[1.25rem] border border-white/10 bg-slate-950/45 p-4">
          <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div class="flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>Sorted by total vulns, then recent last seen activity.</span>
              <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
                Page {{ currentPage }} / {{ pageCount }}
              </span>
            </div>
          </div>
        </div>

        <div v-if="paginatedAssets.length === 0" class="mt-6 rounded-[1.25rem] border border-dashed border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
          No assets match the current filters.
        </div>

        <div v-else class="mt-6 overflow-x-auto">
        <table class="min-w-full divide-y divide-white/8 text-sm">
          <thead>
            <tr class="text-left text-xs uppercase tracking-[0.24em] text-slate-500">
              <th class="px-3 py-3">Host</th>
              <th class="px-3 py-3">IP</th>
              <th class="px-3 py-3">Open Port</th>
              <th class="px-3 py-3">Highest Severity</th>
              <th class="px-3 py-3">Total Vulns</th>
              <th class="px-3 py-3">First Seen</th>
              <th class="px-3 py-3">Last Seen</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/6">
            <tr
              v-for="asset in paginatedAssets"
              :key="asset.id"
              class="cursor-pointer align-top text-slate-200 transition hover:bg-white/[0.03]"
              @click="openAssetDetail(asset)"
            >
              <td class="px-3 py-4">
                <p class="font-semibold text-white">{{ asset.host || "--" }}</p>
              </td>
              <td class="px-3 py-4">
                <div class="flex flex-wrap gap-2">
                  <span
                    v-for="ip in asset.ip_addresses"
                    :key="ip"
                    class="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-200"
                  >
                    {{ ip }}
                  </span>
                  <span v-if="asset.ip_addresses.length === 0" class="text-sm text-slate-400">--</span>
                </div>
              </td>
              <td class="px-3 py-4">
                <div class="flex flex-wrap gap-2">
                  <span
                    v-for="port in asset.open_ports"
                    :key="port"
                    class="rounded-full border border-sky-400/20 bg-sky-400/10 px-2.5 py-1 text-xs text-sky-200"
                  >
                    {{ port }}
                  </span>
                  <span v-if="asset.open_ports.length === 0" class="text-sm text-slate-400">--</span>
                </div>
              </td>
              <td class="px-3 py-4">
                <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em]" :class="severityClasses(asset.highest_severity)">
                  {{ asset.highest_severity || "--" }}
                </span>
              </td>
              <td class="px-3 py-4 text-slate-200">{{ asset.vulnerability_count ?? 0 }}</td>
              <td class="px-3 py-4 text-slate-300">{{ formatDate(asset.first_seen) }}</td>
              <td class="px-3 py-4 text-slate-300">{{ formatDate(asset.last_seen) }}</td>
            </tr>
          </tbody>
        </table>
      </div>

        <div v-if="paginatedAssets.length > 0" class="mt-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <p class="text-sm text-slate-400">
            Showing {{ (currentPage - 1) * pageSize + 1 }} - {{ Math.min(currentPage * pageSize, totalFiltered) }} of {{ totalFiltered }} assets.
          </p>
          <div class="flex flex-wrap items-center gap-2">
            <label class="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-slate-300">
              <span>Rows</span>
              <select v-model="pageSize" class="bg-transparent text-xs font-semibold text-white outline-none">
                <option v-for="size in PAGE_SIZE_OPTIONS" :key="size" :value="size" class="bg-slate-950">
                  {{ size }}
                </option>
              </select>
            </label>
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
              :disabled="!nextCursor || currentPage === pageCount"
              @click="goToNextPage"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </section>
  </AppShell>
</template>
