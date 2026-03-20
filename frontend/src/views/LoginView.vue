<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";

import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";
import teamLogo from "../../testnwatchlogo.jpg";

const router = useRouter();
const authStore = useAuthStore();
const loading = ref(false);
const errorMessage = ref("");
const failedAttempt = ref(false);

const form = reactive({
  username: "",
  password: "",
});

async function submitLogin() {
  loading.value = true;
  errorMessage.value = "";
  failedAttempt.value = false;

  try {
    const { data } = await api.post("/api/auth/login", form);
    authStore.setSession(data.access_token, data.role, data.username);
    await router.push({ name: "dashboard" });
  } catch (error) {
    errorMessage.value = "Login failed. Please verify your credentials.";
    failedAttempt.value = true;
    window.setTimeout(() => {
      failedAttempt.value = false;
    }, 550);
    console.error(error);
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <main class="grid min-h-screen grid-cols-1 overflow-hidden bg-slate-950 lg:grid-cols-[1.1fr_0.9fr]">
    <section class="relative flex items-center justify-center border-b border-red-500/15 px-8 py-12 lg:border-b-0 lg:border-r lg:border-white/10 lg:px-12">
      <div class="absolute inset-0 bg-[radial-gradient(circle_at_18%_18%,rgba(239,68,68,0.28),transparent_24%),radial-gradient(circle_at_78%_32%,rgba(251,146,60,0.16),transparent_18%),linear-gradient(135deg,rgba(2,6,23,0.94),rgba(15,23,42,0.92))]" />
      <div class="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(148,163,184,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.08)_1px,transparent_1px)] [background-size:44px_44px]" />

      <div class="relative z-10 max-w-xl">
        <div class="inline-flex items-center gap-3 rounded-full border border-red-400/20 bg-red-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.28em] text-red-200">
          <span class="h-2 w-2 rounded-full bg-red-400 shadow-[0_0_16px_rgba(248,113,113,0.9)]" />
          T&W Falcon
        </div>

        <div class="mt-8 flex items-center gap-5">
          <div class="flex h-24 w-24 items-center justify-center rounded-[1.75rem] border border-white/10 bg-white/5 p-3 shadow-[0_0_40px_rgba(239,68,68,0.18)] backdrop-blur">
            <img :src="teamLogo" alt="Test And Watch logo" class="h-full w-full rounded-[1.2rem] object-cover" />
          </div>
          <div>
            <p class="text-sm uppercase tracking-[0.36em] text-orange-200/90">External Attack Surface Management</p>
            <h1 class="mt-3 text-2xl font-black uppercase tracking-tight text-white md:text-4xl">
              Test And Watch
            </h1>
          </div>
        </div>

        <p class="mt-8 max-w-2xl text-lg leading-8 text-slate-200/90">
          Professional offensive security operations for teams that need disciplined visibility, fast triage, and
          decision-ready intelligence across exposed internet assets.
        </p>

        <div class="mt-8 grid gap-4 sm:grid-cols-3">
          <article class="rounded-[1.5rem] border border-white/10 bg-white/6 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Mission</p>
            <p class="mt-2 text-sm leading-6 text-slate-200">Continuously detect exposure before attackers operationalize it.</p>
          </article>
          <article class="rounded-[1.5rem] border border-white/10 bg-white/6 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Approach</p>
            <p class="mt-2 text-sm leading-6 text-slate-200">Validated findings, controlled triage, and analyst-friendly workflows.</p>
          </article>
          <article class="rounded-[1.5rem] border border-white/10 bg-white/6 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Audience</p>
            <p class="mt-2 text-sm leading-6 text-slate-200">Built for pentest teams, security leads, and SOC visibility screens.</p>
          </article>
        </div>
      </div>
    </section>

    <section class="relative flex items-center justify-center px-8 py-12">
      <form
        class="w-full max-w-md rounded-[2rem] border border-white/10 bg-slate-900/75 p-8 shadow-2xl shadow-red-950/35 backdrop-blur transition"
        :class="{ 'animate-[login-shake_0.45s_ease-in-out]': failedAttempt }"
        @submit.prevent="submitLogin"
      >
        <p class="text-xs uppercase tracking-[0.32em] text-red-300">Secure Access</p>
        <h2 class="mt-3 text-3xl font-semibold text-white">Operator Login</h2>
        <p class="mt-2 text-sm leading-6 text-slate-400">
          Sign in with your assigned credentials to access the Test And Watch EASM dashboard.
        </p>

        <label class="mt-8 block text-sm text-slate-300">
          Username
          <input
            v-model="form.username"
            class="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-white outline-none transition focus:border-red-400/50"
            type="text"
            autocomplete="username"
          />
        </label>

        <label class="mt-4 block text-sm text-slate-300">
          Password
          <input
            v-model="form.password"
            class="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-white outline-none transition focus:border-red-400/50"
            type="password"
            autocomplete="current-password"
          />
        </label>

        <p v-if="errorMessage" class="mt-4 rounded-2xl border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {{ errorMessage }}
        </p>

        <button
          class="mt-6 w-full rounded-2xl bg-gradient-to-r from-red-500 to-orange-400 px-4 py-3 font-semibold text-slate-950 transition hover:from-red-400 hover:to-orange-300 disabled:cursor-not-allowed disabled:opacity-70"
          :disabled="loading"
          type="submit"
        >
          {{ loading ? "Authenticating..." : "Enter Dashboard" }}
        </button>

        <p class="mt-5 text-xs leading-6 text-slate-500">
          Authorized access only. All activity is monitored for operational integrity and audit readiness.
        </p>
      </form>
    </section>
  </main>
</template>
