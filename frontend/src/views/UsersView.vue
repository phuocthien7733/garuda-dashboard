<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";

import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";

type UserRole = "admin" | "viewer";

type UserRecord = {
  username: string;
  email?: string | null;
  role: UserRole;
  mfa_enabled: boolean;
  created_at?: string | null;
  updated_at?: string | null;
};

const authStore = useAuthStore();

const loading = ref(true);
const saving = ref(false);
const deleting = ref(false);
const searchQuery = ref("");
const errorMessage = ref("");
const successMessage = ref("");
const users = ref<UserRecord[]>([]);
const showModal = ref(false);
const showDeleteModal = ref(false);
const editMode = ref<"create" | "edit">("create");
const deleteTarget = ref<UserRecord | null>(null);
const editingUser = ref<UserRecord | null>(null);

const form = reactive({
  username: "",
  email: "",
  role: "viewer" as UserRole,
  mfaEnabled: false,
  password: "",
});

const filteredUsers = computed(() => {
  const needle = searchQuery.value.trim().toLowerCase();
  if (!needle) {
    return users.value;
  }

  return users.value.filter((user) => {
    return [user.username, user.email ?? "", user.role].some((value) => value.toLowerCase().includes(needle));
  });
});

const totalUsers = computed(() => users.value.length);
const totalAdmins = computed(() => users.value.filter((user) => user.role === "admin").length);
const totalViewers = computed(() => users.value.filter((user) => user.role === "viewer").length);
const totalMfaEnabled = computed(() => users.value.filter((user) => user.mfa_enabled).length);

function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "--";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function roleBadgeClass(role: UserRole) {
  return role === "admin"
    ? "border-red-400/25 bg-red-500/10 text-red-100"
    : "border-blue-400/25 bg-blue-500/10 text-blue-100";
}

function mfaBadgeClass(enabled: boolean) {
  return enabled
    ? "border-orange-400/25 bg-orange-500/10 text-orange-100"
    : "border-white/10 bg-white/[0.04] text-slate-300";
}

async function loadUsers() {
  loading.value = true;
  errorMessage.value = "";

  try {
    const { data } = await api.get<UserRecord[]>("/users");
    users.value = data;
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Unable to load users right now.";
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.username = "";
  form.email = "";
  form.role = "viewer";
  form.mfaEnabled = false;
  form.password = "";
}

function openCreateModal() {
  resetForm();
  editingUser.value = null;
  editMode.value = "create";
  errorMessage.value = "";
  successMessage.value = "";
  showModal.value = true;
}

function openEditModal(user: UserRecord) {
  form.username = user.username;
  form.email = user.email ?? "";
  form.role = user.role;
  form.mfaEnabled = Boolean(user.mfa_enabled);
  form.password = "";
  editingUser.value = user;
  editMode.value = "edit";
  errorMessage.value = "";
  successMessage.value = "";
  showModal.value = true;
}

function requestDelete(user: UserRecord) {
  deleteTarget.value = user;
  errorMessage.value = "";
  successMessage.value = "";
  showDeleteModal.value = true;
}

async function saveUser() {
  errorMessage.value = "";
  successMessage.value = "";

  if (!form.username.trim()) {
    errorMessage.value = "Username is required.";
    return;
  }

  if (!form.email.trim()) {
    errorMessage.value = "Email is required.";
    return;
  }

  if (editMode.value === "create" && !form.password.trim()) {
    errorMessage.value = "Password is required for new users.";
    return;
  }

  if (editMode.value === "edit" && editingUser.value?.username === authStore.username && form.role !== authStore.role) {
    errorMessage.value = "You cannot change your own role from this page.";
    return;
  }

  saving.value = true;

  try {
    const payload = {
      username: form.username.trim(),
      email: form.email.trim().toLowerCase(),
      role: form.role,
      mfa_enabled: form.mfaEnabled,
      password: form.password.trim() || undefined,
    };

    if (editMode.value === "create") {
      await api.post("/users", {
        ...payload,
        password: form.password.trim(),
      });
      successMessage.value = "New user created successfully.";
    } else if (editingUser.value) {
      await api.patch(`/users/${editingUser.value.username}`, payload);
      successMessage.value = "User updated successfully.";
    }

    showModal.value = false;
    await loadUsers();
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Unable to save the user.";
  } finally {
    saving.value = false;
  }
}

async function deleteUser() {
  if (!deleteTarget.value) {
    return;
  }

  deleting.value = true;
  errorMessage.value = "";
  successMessage.value = "";

  try {
    await api.delete(`/users/${deleteTarget.value.username}`);
    successMessage.value = "User deleted successfully.";
    showDeleteModal.value = false;
    deleteTarget.value = null;
    await loadUsers();
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Unable to delete this user.";
  } finally {
    deleting.value = false;
  }
}

onMounted(async () => {
  await loadUsers();
});
</script>

<template>
  <AppShell
    eyebrow="Administration"
    title="User Management"
    description="Manage operator accounts, roles, emails, MFA state, and lifecycle controls from one place."
  >
    <section class="mt-4 space-y-4">
      <div class="grid gap-4 xl:grid-cols-4">
        <article class="rounded-[1.4rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur">
          <p class="text-[11px] uppercase tracking-[0.24em] text-slate-500">Total Users</p>
          <p class="mt-3 text-3xl font-black text-white">{{ totalUsers }}</p>
        </article>

        <article class="rounded-[1.4rem] border border-red-400/15 bg-slate-900/65 p-5 backdrop-blur">
          <p class="text-[11px] uppercase tracking-[0.24em] text-red-300">Admins</p>
          <p class="mt-3 text-3xl font-black text-red-100">{{ totalAdmins }}</p>
        </article>

        <article class="rounded-[1.4rem] border border-blue-400/15 bg-slate-900/65 p-5 backdrop-blur">
          <p class="text-[11px] uppercase tracking-[0.24em] text-blue-300">Viewers</p>
          <p class="mt-3 text-3xl font-black text-blue-100">{{ totalViewers }}</p>
        </article>

        <article class="rounded-[1.4rem] border border-orange-400/15 bg-slate-900/65 p-5 backdrop-blur">
          <p class="text-[11px] uppercase tracking-[0.24em] text-orange-300">MFA Enabled</p>
          <p class="mt-3 text-3xl font-black text-orange-100">{{ totalMfaEnabled }}</p>
        </article>
      </div>

      <section class="rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="text-[11px] uppercase tracking-[0.24em] text-orange-300">Operators</p>
            <h3 class="mt-2 text-2xl font-black text-white">Current Users</h3>
            <p class="mt-2 text-sm text-slate-400">
              Create new accounts, update user information, or remove accounts that are no longer needed.
            </p>
          </div>

          <div class="flex w-full flex-col gap-3 sm:flex-row lg:w-auto">
            <input
              v-model="searchQuery"
              type="text"
              class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40 sm:min-w-72"
              placeholder="Search username, email, or role"
            />
            <button
              type="button"
              class="inline-flex items-center justify-center rounded-[1rem] border border-orange-400/30 bg-orange-500/15 px-5 py-3 text-sm font-semibold text-orange-100 transition hover:border-orange-300/45 hover:bg-orange-500/25"
              @click="openCreateModal"
            >
              Add User
            </button>
          </div>
        </div>

        <div v-if="errorMessage" class="mt-4 rounded-[1rem] border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-100">
          {{ errorMessage }}
        </div>

        <div
          v-if="successMessage"
          class="mt-4 rounded-[1rem] border border-emerald-500/25 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100"
        >
          {{ successMessage }}
        </div>

        <div
          v-if="loading"
          class="mt-5 rounded-[1.25rem] border border-white/10 bg-white/[0.03] px-4 py-10 text-sm text-slate-400"
        >
          Loading users...
        </div>

        <div v-else class="mt-5 overflow-hidden rounded-[1.25rem] border border-white/10">
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-white/10 text-left">
              <thead class="bg-slate-950/80">
                <tr class="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                  <th class="px-4 py-3 font-medium">Username</th>
                  <th class="px-4 py-3 font-medium">Email</th>
                  <th class="px-4 py-3 font-medium">Role</th>
                  <th class="px-4 py-3 font-medium">MFA</th>
                  <th class="px-4 py-3 font-medium">Created At</th>
                  <th class="px-4 py-3 font-medium">Updated At</th>
                  <th class="px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/10 bg-slate-900/40">
                <tr v-for="user in filteredUsers" :key="user.username" class="transition hover:bg-white/[0.03]">
                  <td class="px-4 py-4 text-sm font-semibold text-white">{{ user.username }}</td>
                  <td class="px-4 py-4 text-sm text-slate-300">{{ user.email || "--" }}</td>
                  <td class="px-4 py-4">
                    <span class="inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.18em]" :class="roleBadgeClass(user.role)">
                      {{ user.role }}
                    </span>
                  </td>
                  <td class="px-4 py-4">
                    <span class="inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.18em]" :class="mfaBadgeClass(user.mfa_enabled)">
                      {{ user.mfa_enabled ? "Enabled" : "Disabled" }}
                    </span>
                  </td>
                  <td class="px-4 py-4 text-sm text-slate-400">{{ formatDateTime(user.created_at) }}</td>
                  <td class="px-4 py-4 text-sm text-slate-400">{{ formatDateTime(user.updated_at) }}</td>
                  <td class="px-4 py-4">
                    <div class="flex flex-wrap gap-2">
                      <button
                        type="button"
                        class="rounded-[0.85rem] border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
                        @click="openEditModal(user)"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        class="rounded-[0.85rem] border border-red-400/20 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-100 transition hover:border-red-300/40 hover:bg-red-500/18 disabled:cursor-not-allowed disabled:opacity-50"
                        :disabled="user.username === authStore.username"
                        @click="requestDelete(user)"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
                <tr v-if="filteredUsers.length === 0">
                  <td colspan="7" class="px-4 py-8 text-center text-sm text-slate-500">
                    No users matched the current search.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </section>

    <div
      v-if="showModal"
      class="fixed inset-0 z-[90] flex items-center justify-center bg-slate-950/78 px-4 py-8 backdrop-blur-sm"
    >
      <div class="w-full max-w-2xl rounded-[1.7rem] border border-white/10 bg-slate-950/98 p-6 shadow-2xl shadow-black/45">
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-[11px] uppercase tracking-[0.24em] text-orange-300">{{ editMode === "create" ? "Create" : "Update" }}</p>
            <h3 class="mt-2 text-2xl font-black text-white">{{ editMode === "create" ? "Add New User" : "Edit User" }}</h3>
          </div>
          <button
            type="button"
            class="rounded-[0.9rem] border border-white/10 bg-white/[0.04] px-3 py-2 text-sm text-slate-300 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="showModal = false"
          >
            Close
          </button>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="space-y-2">
            <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Username</span>
            <input
              v-model="form.username"
              type="text"
              class="w-full rounded-[1rem] border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
            />
          </label>

          <label class="space-y-2">
            <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Email</span>
            <input
              v-model="form.email"
              type="email"
              class="w-full rounded-[1rem] border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
            />
          </label>

          <label class="space-y-2">
            <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Role</span>
            <select
              v-model="form.role"
              class="w-full rounded-[1rem] border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
            >
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </select>
          </label>

          <label class="space-y-2">
            <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Password</span>
            <input
              v-model="form.password"
              type="password"
              class="w-full rounded-[1rem] border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
              :placeholder="editMode === 'create' ? 'Required for new user' : 'Leave empty to keep current password'"
            />
          </label>
        </div>

        <div class="mt-4 rounded-[1.15rem] border border-white/10 bg-white/[0.03] p-4">
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-sm font-semibold text-white">Enable MFA</p>
              <p class="mt-1 text-xs leading-6 text-slate-500">
                Decide whether this user must pass the email MFA challenge during sign-in.
              </p>
            </div>
            <button
              type="button"
              class="relative inline-flex h-7 w-14 shrink-0 rounded-full border transition"
              :class="form.mfaEnabled ? 'border-orange-400/40 bg-orange-500/20' : 'border-white/10 bg-white/[0.05]'"
              @click="form.mfaEnabled = !form.mfaEnabled"
            >
              <span
                class="absolute top-1 h-5 w-5 rounded-full transition"
                :class="form.mfaEnabled ? 'left-8 bg-orange-300 shadow-[0_0_24px_rgba(251,146,60,0.55)]' : 'left-1 bg-slate-400'"
              />
            </button>
          </div>
        </div>

        <div class="mt-6 flex justify-end gap-3">
          <button
            type="button"
            class="rounded-[1rem] border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="showModal = false"
          >
            Cancel
          </button>
          <button
            type="button"
            :disabled="saving"
            class="rounded-[1rem] border border-orange-400/30 bg-orange-500/15 px-5 py-3 text-sm font-semibold text-orange-100 transition hover:border-orange-300/45 hover:bg-orange-500/25 disabled:cursor-not-allowed disabled:opacity-60"
            @click="saveUser"
          >
            {{ saving ? "Saving..." : editMode === "create" ? "Create User" : "Save Changes" }}
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="showDeleteModal && deleteTarget"
      class="fixed inset-0 z-[90] flex items-center justify-center bg-slate-950/78 px-4 py-8 backdrop-blur-sm"
    >
      <div class="w-full max-w-lg rounded-[1.7rem] border border-white/10 bg-slate-950/98 p-6 shadow-2xl shadow-black/45">
        <p class="text-[11px] uppercase tracking-[0.24em] text-red-300">Danger Zone</p>
        <h3 class="mt-2 text-2xl font-black text-white">Delete User</h3>
        <p class="mt-3 text-sm leading-7 text-slate-400">
          You are about to remove <span class="font-semibold text-white">{{ deleteTarget.username }}</span>. This action cannot be undone.
        </p>

        <div class="mt-6 flex justify-end gap-3">
          <button
            type="button"
            class="rounded-[1rem] border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08]"
            @click="showDeleteModal = false"
          >
            Cancel
          </button>
          <button
            type="button"
            :disabled="deleting"
            class="rounded-[1rem] border border-red-400/25 bg-red-500/10 px-5 py-3 text-sm font-semibold text-red-100 transition hover:border-red-300/45 hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            @click="deleteUser"
          >
            {{ deleting ? "Deleting..." : "Delete User" }}
          </button>
        </div>
      </div>
    </div>
  </AppShell>
</template>
