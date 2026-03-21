<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";

import AppShell from "@/components/layout/AppShell.vue";
import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";

type SessionProfile = {
  username: string;
  email?: string | null;
  role: "admin" | "viewer";
  created_at?: string | null;
  mfa_enabled?: boolean;
};

type TokenResponse = {
  access_token: string;
  username: string;
  role: "admin" | "viewer";
  email?: string | null;
};

const authStore = useAuthStore();

const loading = ref(true);
const saving = ref(false);
const mfaSaving = ref(false);
const errorMessage = ref("");
const successMessage = ref("");
const initialMfaEnabled = ref(false);
const savedUsername = ref("");
const savedEmail = ref("");

const form = reactive({
  username: "",
  email: "",
  role: "viewer" as "admin" | "viewer",
  createdAt: "",
  mfaEnabled: false,
  currentPassword: "",
  newPassword: "",
  confirmPassword: "",
});

const createdAtLabel = computed(() => formatDateTime(form.createdAt));
const passwordUpdateRequested = computed(() => Boolean(form.currentPassword || form.newPassword || form.confirmPassword));

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

async function loadProfile() {
  loading.value = true;
  errorMessage.value = "";

  try {
    const { data } = await api.get<SessionProfile>("/auth/me");
    form.username = data.username;
    form.email = data.email ?? "";
    form.role = data.role;
    form.createdAt = data.created_at ?? "";
    form.mfaEnabled = Boolean(data.mfa_enabled);
    initialMfaEnabled.value = form.mfaEnabled;
    savedUsername.value = data.username;
    savedEmail.value = data.email ?? "";
  } catch (error) {
    console.error(error);
    errorMessage.value = "Unable to load your profile information right now.";
  } finally {
    loading.value = false;
  }
}

async function saveProfile() {
  errorMessage.value = "";
  successMessage.value = "";

  if (!form.username.trim()) {
    errorMessage.value = "Username is required.";
    return;
  }

  if (!form.email.trim()) {
    errorMessage.value = "Email is required for future MFA delivery.";
    return;
  }

  if (passwordUpdateRequested.value) {
    if (!form.currentPassword) {
      errorMessage.value = "Current password is required to set a new password.";
      return;
    }

    if (!form.newPassword) {
      errorMessage.value = "New password cannot be empty.";
      return;
    }

    if (form.newPassword !== form.confirmPassword) {
      errorMessage.value = "New password confirmation does not match.";
      return;
    }
  }

  saving.value = true;

  try {
    const payload = {
      username: form.username.trim(),
      email: form.email.trim().toLowerCase(),
      mfa_enabled: form.mfaEnabled,
      current_password: form.currentPassword || undefined,
      new_password: form.newPassword || undefined,
    };

    const { data } = await api.patch<TokenResponse>("/auth/me", payload);
    authStore.setSession(data.access_token, data.role, data.username);
    form.username = data.username;
    form.email = data.email ?? form.email;
    form.role = data.role;
    initialMfaEnabled.value = form.mfaEnabled;
    savedUsername.value = form.username;
    savedEmail.value = form.email;
    form.currentPassword = "";
    form.newPassword = "";
    form.confirmPassword = "";
    successMessage.value = "Your profile has been updated successfully.";
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Profile update failed.";
  } finally {
    saving.value = false;
  }
}

onMounted(async () => {
  await loadProfile();
});

async function toggleMfaState() {
  errorMessage.value = "";
  successMessage.value = "";

  mfaSaving.value = true;
  const nextMfaState = !form.mfaEnabled;

  try {
    const { data } = await api.patch<TokenResponse>("/auth/me", {
      username: savedUsername.value,
      email: savedEmail.value.trim().toLowerCase(),
      mfa_enabled: nextMfaState,
    });

    authStore.setSession(data.access_token, data.role, data.username);
    form.username = data.username;
    form.email = data.email ?? form.email;
    form.mfaEnabled = nextMfaState;
    initialMfaEnabled.value = nextMfaState;
    savedUsername.value = form.username;
    savedEmail.value = form.email;
    successMessage.value = nextMfaState
      ? "MFA has been activated successfully."
      : "MFA has been deactivated successfully.";
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Unable to update MFA right now.";
  } finally {
    mfaSaving.value = false;
  }
}
</script>

<template>
  <AppShell
    eyebrow="Identity"
    title="Edit User Information"
    description="Keep your account profile current and prepare your mailbox for future MFA delivery."
  >
    <section class="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,0.7fr)]">
      <article class="rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur">
        <div class="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
          <div>
            <p class="text-[11px] uppercase tracking-[0.24em] text-orange-300">Profile</p>
            <h3 class="mt-2 text-2xl font-black text-white">User Information</h3>
            <p class="mt-2 max-w-2xl text-sm text-slate-400">
              Update your primary identity details here. The email address you set now will be used later for MFA and
              account security workflows.
            </p>
          </div>
          <div class="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-right">
            <p class="text-[11px] uppercase tracking-[0.24em] text-slate-500">Signed In As</p>
            <p class="mt-2 text-sm font-semibold text-white">{{ authStore.username }}</p>
            <p class="mt-1 text-xs text-slate-500">{{ form.role }}</p>
          </div>
        </div>

        <div
          v-if="loading"
          class="mt-5 rounded-[1.25rem] border border-white/10 bg-white/[0.03] px-4 py-10 text-sm text-slate-400"
        >
          Loading your profile...
        </div>

        <form v-else class="mt-5 space-y-5" @submit.prevent="saveProfile">
          <div v-if="errorMessage" class="rounded-[1rem] border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-100">
            {{ errorMessage }}
          </div>

          <div
            v-if="successMessage"
            class="rounded-[1rem] border border-emerald-500/25 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100"
          >
            {{ successMessage }}
          </div>

          <div class="grid gap-4 md:grid-cols-2">
            <label class="space-y-2">
              <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Username</span>
              <input
                v-model="form.username"
                type="text"
                class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
                placeholder="Enter your username"
              />
            </label>

            <label class="space-y-2">
              <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Email</span>
              <input
                v-model="form.email"
                type="email"
                class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
                placeholder="name@testandwatch.com"
              />
            </label>
          </div>

          <div class="grid gap-4 md:grid-cols-2">
            <label class="space-y-2">
              <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Role</span>
              <input
                :value="form.role"
                type="text"
                disabled
                class="w-full rounded-[1rem] border border-white/10 bg-slate-950/50 px-4 py-3 text-sm text-slate-400 outline-none"
              />
            </label>

            <label class="space-y-2">
              <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Created At</span>
              <input
                :value="createdAtLabel"
                type="text"
                disabled
                class="w-full rounded-[1rem] border border-white/10 bg-slate-950/50 px-4 py-3 text-sm text-slate-400 outline-none"
              />
            </label>
          </div>

          <div class="rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4">
            <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <p class="text-sm font-semibold text-white">Email MFA Protection</p>
                <p class="mt-1 text-xs leading-6 text-slate-500">
                  Enable a second-factor email challenge for operator login. Changes are applied immediately when you activate or deactivate MFA.
                </p>
                <div class="mt-3 inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.2em]"
                  :class="form.mfaEnabled
                    ? 'border-orange-400/30 bg-orange-500/10 text-orange-100'
                    : 'border-white/10 bg-white/[0.04] text-slate-300'"
                >
                  <span
                    class="h-2 w-2 rounded-full"
                    :class="form.mfaEnabled
                      ? 'bg-orange-300 shadow-[0_0_16px_rgba(251,146,60,0.8)]'
                      : 'bg-slate-500'"
                  />
                  {{ form.mfaEnabled ? "MFA Active" : "MFA Inactive" }}
                </div>
              </div>

              <button
                type="button"
                class="inline-flex items-center justify-center rounded-[1rem] border px-4 py-2.5 text-sm font-semibold transition"
                :class="form.mfaEnabled
                  ? 'border-red-400/30 bg-red-500/10 text-red-100 hover:border-red-300/45 hover:bg-red-500/18'
                  : 'border-orange-400/30 bg-orange-500/12 text-orange-100 hover:border-orange-300/45 hover:bg-orange-500/22'"
                :disabled="mfaSaving"
                @click="toggleMfaState"
              >
                {{ mfaSaving ? "Updating MFA..." : form.mfaEnabled ? "Deactivate MFA" : "Activate MFA" }}
              </button>
            </div>
          </div>

          <div class="rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4">
            <div class="flex flex-col gap-1 md:flex-row md:items-end md:justify-between">
              <div>
                <p class="text-sm font-semibold text-white">Password Rotation</p>
                <p class="mt-1 text-xs text-slate-500">
                  Leave these fields empty if you only want to update username or email.
                </p>
              </div>
              <p class="text-[11px] uppercase tracking-[0.22em] text-slate-500">Optional</p>
            </div>

            <div class="mt-4 grid gap-4 md:grid-cols-3">
              <label class="space-y-2">
                <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Current Password</span>
                <input
                  v-model="form.currentPassword"
                  type="password"
                  class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
                  placeholder="Required for password changes"
                />
              </label>

              <label class="space-y-2">
                <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">New Password</span>
                <input
                  v-model="form.newPassword"
                  type="password"
                  class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
                  placeholder="Set a new password"
                />
              </label>

              <label class="space-y-2">
                <span class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Confirm Password</span>
                <input
                  v-model="form.confirmPassword"
                  type="password"
                  class="w-full rounded-[1rem] border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-orange-400/40"
                  placeholder="Repeat the new password"
                />
              </label>
            </div>
          </div>

          <div class="flex flex-col gap-3 border-t border-white/10 pt-4 md:flex-row md:items-center md:justify-between">
            <p class="text-xs text-slate-500">
              Saving your profile will refresh the current session token if your username changes.
            </p>
            <button
              type="submit"
              :disabled="saving"
              class="inline-flex items-center justify-center rounded-[1rem] border border-orange-400/30 bg-orange-500/15 px-5 py-3 text-sm font-semibold text-orange-100 transition hover:border-orange-300/45 hover:bg-orange-500/25 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {{ saving ? "Updating..." : "Update Information" }}
            </button>
          </div>
        </form>
      </article>

      <article class="rounded-[1.6rem] border border-white/10 bg-slate-900/65 p-5 backdrop-blur">
        <p class="text-[11px] uppercase tracking-[0.24em] text-orange-300">Security</p>
        <h3 class="mt-2 text-2xl font-black text-white">Your Information</h3>
        <p class="mt-3 text-sm text-slate-400">

        </p>

        <div class="mt-5 space-y-3">
          <div class="rounded-[1.1rem] border border-white/10 bg-white/[0.03] p-4">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Primary Email</p>
            <p class="mt-2 text-sm font-semibold text-white">{{ form.email || "Not configured yet" }}</p>
          </div>

          <div class="rounded-[1.1rem] border border-white/10 bg-white/[0.03] p-4">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">MFA Status</p>
            <p class="mt-2 text-sm font-semibold" :class="form.mfaEnabled ? 'text-orange-200' : 'text-slate-300'">
              {{ form.mfaEnabled ? "Active on login" : "Disabled" }}
            </p>
          </div>

          <div class="rounded-[1.1rem] border border-white/10 bg-white/[0.03] p-4">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Role Scope</p>
            <p class="mt-2 text-sm text-slate-300">
              {{ form.role === "admin" ? "Full administrative control across the EASM platform." : "Read-only access for monitoring and review." }}
            </p>
          </div>

          <div class="rounded-[1.1rem] border border-white/10 bg-white/[0.03] p-4">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Operational Note</p>
            <p class="mt-2 text-sm text-slate-300">
          The email address in your profile will be the delivery channel for future MFA codes and account recovery
          notices.
            </p>
          </div>
        </div>
      </article>
    </section>
  </AppShell>
</template>
