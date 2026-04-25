<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";

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
const authStore = useAuthStore();
const maps = ref<HuntingMapSummary[]>([]);
const loading = ref(false);
const showCreateModal = ref(false);
const newName = ref("");
const newDescription = ref("");
const creating = ref(false);
const deletingId = ref("");

// Delete confirmation modal state
const deleteTarget = ref<HuntingMapSummary | null>(null);
const deleteConfirmText = ref("");
const DELETE_PHRASE = "I need delete this map";
const deleteError = ref("");

function openDeleteModal(m: HuntingMapSummary) {
  deleteTarget.value = m;
  deleteConfirmText.value = "";
  deleteError.value = "";
}

function closeDeleteModal() {
  deleteTarget.value = null;
  deleteConfirmText.value = "";
  deleteError.value = "";
}

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
  if (deleteConfirmText.value !== DELETE_PHRASE) {
    deleteError.value = "Confirmation phrase does not match.";
    return;
  }
  deletingId.value = id;
  try {
    await api.delete(`/hunting-maps/${encodeURIComponent(id)}`);
    maps.value = maps.value.filter((m) => m.id !== id);
    closeDeleteModal();
  } catch (error: unknown) {
    const msg = (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
    deleteError.value = msg || "Failed to delete map.";
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
  if (e.key === "Escape") {
    if (deleteTarget.value) { closeDeleteModal(); return; }
    showCreateModal.value = false;
  }
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
              :disabled="m.created_by !== authStore.username"
              :title="m.created_by !== authStore.username ? `Only ${m.created_by} can delete this map` : 'Delete map'"
              @click.stop="openDeleteModal(m)"
            >
              Delete
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

  <!-- Delete confirmation modal -->
  <Teleport to="body">
    <div
      v-if="deleteTarget"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4 py-6 backdrop-blur-sm"
      @click.self="closeDeleteModal"
    >
      <div class="w-full max-w-md rounded-[1.6rem] border border-red-400/20 bg-slate-900 p-6 shadow-2xl shadow-black/50">
        <!-- Header -->
        <div class="flex items-start gap-3">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-red-400/20 bg-red-500/10 text-red-300">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            </svg>
          </div>
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.28em] text-red-400">Destructive Action</p>
            <h3 class="mt-1 text-lg font-semibold text-white">Delete Hunting Map</h3>
          </div>
        </div>

        <!-- Warning -->
        <div class="mt-4 rounded-xl border border-red-400/15 bg-red-500/[0.06] px-4 py-3">
          <p class="text-sm text-slate-300">
            You're deleting the hunting map
            <span class="font-semibold text-white">"{{ deleteTarget.name }}"</span>.
            This action will permanently delete the map, the entire chat discussion, and node tags.
            <span class="font-semibold text-red-300">We cannot restore.</span>
          </p>
        </div>

        <!-- Confirmation input -->
        <div class="mt-5">
          <p class="text-xs text-slate-400">
            Input the following phrase to confirm:
            <code class="ml-1 rounded bg-white/[0.06] px-1.5 py-0.5 text-xs text-orange-300">{{ DELETE_PHRASE }}</code>
          </p>
          <input
            v-model="deleteConfirmText"
            type="text"
            :placeholder="DELETE_PHRASE"
            class="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2.5 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-red-400/40"
            @keydown.enter="deleteMap(deleteTarget.id)"
          >
          <p v-if="deleteError" class="mt-2 text-xs text-red-400">{{ deleteError }}</p>
        </div>

        <!-- Actions -->
        <div class="mt-6 flex justify-end gap-2">
          <button
            type="button"
            class="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="closeDeleteModal"
          >
            Cancel
          </button>
          <button
            type="button"
            class="rounded-full border border-red-400/25 bg-red-500/15 px-5 py-2 text-sm font-semibold text-red-200 transition hover:border-red-400/40 hover:bg-red-500/25 disabled:cursor-not-allowed disabled:opacity-40"
            :disabled="deleteConfirmText !== DELETE_PHRASE || !!deletingId"
            @click="deleteMap(deleteTarget.id)"
          >
            {{ deletingId ? 'Deleting...' : 'Permanently Delete' }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>
