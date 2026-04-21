<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";

type HuntingMapSummary = {
  id: string;
  name: string;
  description: string;
  asset_count: number;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
};

const router = useRouter();
const maps = ref<HuntingMapSummary[]>([]);
const loading = ref(false);
const showCreateModal = ref(false);
const newName = ref("");
const newDescription = ref("");
const creating = ref(false);
const deletingId = ref("");

async function fetchMaps() {
  loading.value = true;
  try {
    const { data } = await api.get<{ items: HuntingMapSummary[] }>("/hunting-maps");
    maps.value = data.items ?? [];
  } catch (error) {
    console.error(error);
  } finally {
    loading.value = false;
  }
}

function openCreateModal() {
  newName.value = "";
  newDescription.value = "";
  showCreateModal.value = true;
}

async function createMap() {
  if (!newName.value.trim()) return;
  creating.value = true;
  try {
    const { data } = await api.post<{ id: string }>("/hunting-maps", {
      name: newName.value.trim(),
      description: newDescription.value.trim(),
    });
    showCreateModal.value = false;
    await router.push({ name: "hunting-map-detail", params: { id: data.id } });
  } catch (error) {
    console.error(error);
  } finally {
    creating.value = false;
  }
}

async function deleteMap(id: string) {
  deletingId.value = id;
  try {
    await api.delete(`/hunting-maps/${encodeURIComponent(id)}`);
    maps.value = maps.value.filter((m) => m.id !== id);
  } catch (error) {
    console.error(error);
  } finally {
    deletingId.value = "";
  }
}

function openMap(id: string) {
  router.push({ name: "hunting-map-detail", params: { id } });
}

function formatDate(value: string | null) {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "--";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}-${pad(d.getMonth() + 1)}-${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function handleEscape(e: KeyboardEvent) {
  if (e.key === "Escape") showCreateModal.value = false;
}

onMounted(() => {
  fetchMaps();
  window.addEventListener("keydown", handleEscape);
});
</script>

<template>
  <AppShell
    eyebrow="T&W Garuda"
    title="Hunting Maps"
    description="Build campaign maps for Red Team operations. Select assets, visualize attack surface, and prioritize targets."
  >
    <section class="mt-4 rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur-xl">
      <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">Campaigns</p>
          <h3 class="mt-2 text-xl font-semibold text-white">Saved Hunting Maps</h3>
          <p class="mt-1 text-sm text-slate-400">
            Select an existing campaign or create a new one.
          </p>
        </div>
        <button
          type="button"
          class="rounded-full border border-orange-400/20 bg-orange-400/10 px-5 py-2.5 text-sm font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18"
          @click="openCreateModal"
        >
          + Create New Map
        </button>
      </div>

      <div v-if="loading" class="mt-6 rounded-[1.25rem] border border-white/10 bg-slate-950/50 px-5 py-10 text-center text-sm text-slate-400">
        Loading hunting maps...
      </div>

      <div v-else-if="maps.length === 0" class="mt-6 rounded-[1.25rem] border border-dashed border-white/10 bg-slate-950/50 px-5 py-10 text-center">
        <p class="text-sm text-slate-400">No hunting maps yet.</p>
        <button
          type="button"
          class="mt-4 rounded-full border border-orange-400/20 bg-orange-400/10 px-5 py-2 text-sm font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18"
          @click="openCreateModal"
        >
          Create your first campaign
        </button>
      </div>

      <div v-else class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article
          v-for="m in maps"
          :key="m.id"
          class="group cursor-pointer rounded-[1.35rem] border border-white/10 bg-slate-950/55 p-5 transition hover:border-orange-400/25 hover:bg-orange-400/[0.04]"
          @click="openMap(m.id)"
        >
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0 flex-1">
              <h4 class="truncate text-base font-semibold text-white group-hover:text-orange-100">{{ m.name }}</h4>
              <p v-if="m.description" class="mt-1 line-clamp-2 text-sm text-slate-400">{{ m.description }}</p>
            </div>
            <button
              type="button"
              class="shrink-0 rounded-full border border-red-400/20 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-200 opacity-0 transition hover:border-red-400/35 hover:bg-red-500/18 group-hover:opacity-100 disabled:opacity-50"
              :disabled="deletingId === m.id"
              @click.stop="deleteMap(m.id)"
            >
              {{ deletingId === m.id ? '...' : 'Delete' }}
            </button>
          </div>
          <div class="mt-4 flex flex-wrap items-center gap-2">
            <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs font-semibold text-slate-300">
              {{ m.asset_count }} asset{{ m.asset_count !== 1 ? 's' : '' }}
            </span>
            <span class="text-xs text-slate-500">Updated {{ formatDate(m.updated_at) }}</span>
          </div>
          <p class="mt-2 text-xs text-slate-500">by {{ m.created_by }}</p>
        </article>
      </div>
    </section>

    <!-- Create modal -->
    <div
      v-if="showCreateModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/78 px-4 py-6 backdrop-blur-sm"
      @click.self="showCreateModal = false"
    >
      <div class="w-full max-w-lg rounded-[1.6rem] border border-white/10 bg-slate-900 p-6 shadow-2xl shadow-black/40">
        <p class="text-xs font-semibold uppercase tracking-[0.28em] text-slate-500">New Campaign</p>
        <h3 class="mt-2 text-xl font-semibold text-white">Create Hunting Map</h3>

        <label class="mt-5 block rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
          Campaign Name
          <input
            v-model="newName"
            type="text"
            placeholder="e.g. Red Team Q2 2026"
            class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
            @keydown.enter="createMap"
          >
        </label>

        <label class="mt-3 block rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-400">
          Description (optional)
          <textarea
            v-model="newDescription"
            rows="3"
            placeholder="Campaign objective, scope, notes..."
            class="mt-2 w-full resize-none rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-medium tracking-normal text-white outline-none transition placeholder:text-slate-500 focus:border-orange-400/35"
          />
        </label>

        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="showCreateModal = false"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-full border border-orange-400/20 bg-orange-400/10 px-5 py-2 text-sm font-semibold text-orange-100 transition hover:border-orange-400/35 hover:bg-orange-400/18 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="!newName.trim() || creating"
            @click="createMap"
          >
            {{ creating ? 'Creating...' : 'Create Map' }}
          </button>
        </div>
      </div>
    </div>
  </AppShell>
</template>
