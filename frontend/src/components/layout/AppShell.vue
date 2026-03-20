<script setup lang="ts">
import { computed, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

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

const props = defineProps<{
  eyebrow: string;
  title: string;
  description?: string;
}>();

const authStore = useAuthStore();
const route = useRoute();
const router = useRouter();
const sidebarExpanded = ref(localStorage.getItem("easm_sidebar_expanded") !== "false");

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

const visibleMenuItems = computed(() => menuItems.filter((item) => !item.adminOnly || authStore.isAdmin));

function toggleSidebar() {
  sidebarExpanded.value = !sidebarExpanded.value;
  localStorage.setItem("easm_sidebar_expanded", String(sidebarExpanded.value));
  window.dispatchEvent(new CustomEvent("easm-sidebar-change"));
}

function isActive(item: MenuItem) {
  if (!item.route?.name) {
    return false;
  }

  if (item.route.name === "assets") {
    return route.name === "assets" || route.name === "asset-profile";
  }

  return route.name === item.route.name;
}

async function navigateTo(item: MenuItem) {
  if (item.route) {
    await router.push(item.route);
  }
}

async function logout() {
  try {
    await api.post("/api/auth/logout");
  } catch (error) {
    console.error(error);
  } finally {
    authStore.clearSession();
    await router.push({ name: "login" });
  }
}
</script>

<template>
  <main class="min-h-screen bg-transparent p-4 md:p-5">
    <div class="flex min-h-[calc(100vh-2rem)] gap-4">
      <aside
        class="flex shrink-0 flex-col rounded-[1.5rem] border border-white/10 bg-slate-900/75 p-2.5 backdrop-blur transition-all duration-300"
        :class="sidebarExpanded ? 'w-56' : 'w-20'"
      >
        <div class="flex justify-center border-b border-white/10 pb-2.5">
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-red-400/20 bg-red-500/10 text-red-200"
            type="button"
            @click="toggleSidebar"
          >
            <svg viewBox="0 0 24 24" class="h-5 w-5 fill-none stroke-current stroke-2">
              <path d="M4 6h16M4 12h16M4 18h16" stroke-linecap="round" />
            </svg>
          </button>
        </div>

        <nav class="mt-3 flex-1 space-y-2">
          <button
            v-for="item in visibleMenuItems"
            :key="item.name"
            class="flex w-full rounded-[1.15rem] border px-2 py-2 text-left transition"
            :class="[
              sidebarExpanded ? 'items-center gap-3' : 'justify-center',
              isActive(item)
                ? 'border-orange-400/30 bg-orange-400/10 text-white'
                : 'border-transparent bg-white/[0.03] text-slate-300 hover:border-white/10 hover:bg-white/[0.05]',
            ]"
            type="button"
            @click="navigateTo(item)"
          >
            <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-slate-950/70">
              <svg viewBox="0 0 24 24" class="h-5 w-5 fill-none stroke-current stroke-2">
                <path :d="item.iconPath" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </span>

            <span v-if="sidebarExpanded" class="min-w-0">
              <span class="block text-sm font-semibold">{{ item.label }}</span>
              <span class="mt-0.5 block truncate text-[11px] text-slate-500">{{ item.description }}</span>
            </span>
          </button>
        </nav>

        <div class="border-t border-white/10 pt-2.5">
          <button
            class="flex w-full rounded-[1.15rem] border border-white/10 px-2 py-2 text-left text-slate-200 transition hover:bg-white/[0.05]"
            :class="sidebarExpanded ? 'items-center gap-3' : 'justify-center'"
            type="button"
            @click="logout"
          >
            <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-slate-950/70">
              <svg viewBox="0 0 24 24" class="h-5 w-5 fill-none stroke-current stroke-2">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </span>
            <span v-if="sidebarExpanded" class="text-sm font-semibold">Logout</span>
          </button>
        </div>
      </aside>

      <section class="min-w-0 flex-1">
        <header class="rounded-[1.25rem] border border-white/10 bg-slate-900/60 px-4 py-2.5 backdrop-blur">
          <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <p class="text-[10px] uppercase tracking-[0.22em] text-orange-300">{{ props.eyebrow }}</p>
              <h2 class="mt-1 text-lg font-bold text-white">{{ props.title }}</h2>
              <p v-if="props.description" class="mt-1 text-sm text-slate-400">{{ props.description }}</p>
            </div>
            <div class="flex items-center gap-2">
              <slot name="header-actions">
                <span class="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-slate-300">
                  {{ authStore.username }}
                </span>
                <span class="rounded-full border border-orange-400/30 bg-orange-400/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-orange-200">
                  {{ authStore.role }}
                </span>
              </slot>
            </div>
          </div>
        </header>

        <slot />
      </section>
    </div>
  </main>
</template>
