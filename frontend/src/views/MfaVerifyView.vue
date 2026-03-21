<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";

import api from "@/services/api";
import { useAuthStore } from "@/stores/auth";
import teamLogo from "../../testnwatchlogo.jpg";

type TokenResponse = {
  access_token: string;
  username: string;
  role: "admin" | "viewer";
};

type MfaChallengeResponse = {
  challenge_id: string;
  username: string;
  masked_email: string;
  challenge_expires_in_seconds: number;
};

const authStore = useAuthStore();
const router = useRouter();

const form = reactive({
  code: "",
});

const loading = ref(false);
const resending = ref(false);
const errorMessage = ref("");
const successMessage = ref("");
const nowTick = ref(Date.now());
let countdownInterval: number | null = null;

const challenge = computed(() => authStore.mfaChallenge);
const challengeExpiresLabel = computed(() => {
  const expiresAt = challenge.value?.expiresAt ?? 0;
  const remainingMs = Math.max(expiresAt - nowTick.value, 0);
  const totalSeconds = Math.floor(remainingMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
});

async function submitVerification() {
  if (!challenge.value) {
    await router.push({ name: "login" });
    return;
  }

  loading.value = true;
  errorMessage.value = "";
  successMessage.value = "";

  try {
    const { data } = await api.post<TokenResponse>("/auth/mfa/verify", {
      challenge_id: challenge.value.challengeId,
      code: form.code.trim(),
    });
    authStore.clearMfaChallenge();
    authStore.setSession(data.access_token, data.role, data.username);
    await router.push({ name: "dashboard" });
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Verification failed.";
  } finally {
    loading.value = false;
  }
}

async function resendCode() {
  if (!challenge.value) {
    await router.push({ name: "login" });
    return;
  }

  resending.value = true;
  errorMessage.value = "";
  successMessage.value = "";

  try {
    const { data } = await api.post<MfaChallengeResponse>("/auth/mfa/resend", {
      challenge_id: challenge.value.challengeId,
    });
    authStore.setMfaChallenge(
      data.challenge_id,
      data.username,
      data.masked_email,
      data.challenge_expires_in_seconds,
    );
    successMessage.value = "A fresh verification code has been sent to your mailbox.";
  } catch (error: any) {
    console.error(error);
    errorMessage.value = error?.response?.data?.detail ?? "Unable to resend the MFA code.";
  } finally {
    resending.value = false;
  }
}

onMounted(() => {
  countdownInterval = window.setInterval(() => {
    nowTick.value = Date.now();
  }, 1000);
});

onBeforeUnmount(() => {
  if (countdownInterval !== null) {
    window.clearInterval(countdownInterval);
  }
});
</script>

<template>
  <main class="grid min-h-screen grid-cols-1 overflow-hidden bg-slate-950 lg:grid-cols-[1.05fr_0.95fr]">
    <section class="relative flex items-center justify-center border-b border-red-500/15 px-8 py-12 lg:border-b-0 lg:border-r lg:border-white/10 lg:px-12">
      <div class="absolute inset-0 bg-[radial-gradient(circle_at_18%_18%,rgba(239,68,68,0.28),transparent_24%),radial-gradient(circle_at_78%_32%,rgba(251,146,60,0.16),transparent_18%),linear-gradient(135deg,rgba(2,6,23,0.94),rgba(15,23,42,0.92))]" />
      <div class="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(148,163,184,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.08)_1px,transparent_1px)] [background-size:44px_44px]" />

      <div class="relative z-10 max-w-xl">
        <div class="inline-flex items-center gap-3 rounded-full border border-red-400/20 bg-red-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.28em] text-red-200">
          <span class="h-2 w-2 rounded-full bg-red-400 shadow-[0_0_16px_rgba(248,113,113,0.9)]" />
          T&W Secure Relay
        </div>

        <div class="mt-8 flex items-center gap-5">
          <div class="flex h-24 w-24 items-center justify-center rounded-[1.75rem] border border-white/10 bg-white/5 p-3 shadow-[0_0_40px_rgba(239,68,68,0.18)] backdrop-blur">
            <img :src="teamLogo" alt="Test And Watch logo" class="h-full w-full rounded-[1.2rem] object-cover" />
          </div>
          <div>
            <p class="text-sm uppercase tracking-[0.36em] text-orange-200/90">Multi-Factor Authentication</p>
            <h1 class="mt-3 text-2xl font-black uppercase tracking-tight text-white md:text-4xl">
              Verification Gateway
            </h1>
          </div>
        </div>

        <p class="mt-8 max-w-2xl text-lg leading-8 text-slate-200/90">
          A second verification barrier protects operator access before mission dashboards and attack-surface data are exposed.
        </p>

        <div class="mt-8 grid gap-4 sm:grid-cols-2">
          <article class="rounded-[1.5rem] border border-white/10 bg-white/6 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Delivery Channel</p>
            <p class="mt-2 text-sm leading-6 text-slate-200">{{ challenge?.maskedEmail || "Mailbox unavailable" }}</p>
          </article>
          <article class="rounded-[1.5rem] border border-white/10 bg-white/6 p-4 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.22em] text-slate-400">Challenge Timer</p>
            <p class="mt-2 text-sm leading-6 text-slate-200">{{ challengeExpiresLabel }}</p>
          </article>
        </div>
      </div>
    </section>

    <section class="relative flex items-center justify-center px-8 py-12">
      <form
        class="w-full max-w-md rounded-[2rem] border border-white/10 bg-slate-900/75 p-8 shadow-2xl shadow-red-950/35 backdrop-blur transition"
        @submit.prevent="submitVerification"
      >
        <p class="text-xs uppercase tracking-[0.32em] text-red-300">Operator Challenge</p>
        <h2 class="mt-3 text-3xl font-semibold text-white">Verify Access</h2>
        <p class="mt-2 text-sm leading-6 text-slate-400">
          Enter the verification code sent to <span class="font-semibold text-slate-200">{{ challenge?.maskedEmail }}</span>.
        </p>

        <label class="mt-8 block text-sm text-slate-300">
          Verification Code
          <input
            v-model="form.code"
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
            class="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-4 text-center text-3xl font-black tracking-[0.45em] text-white outline-none transition focus:border-red-400/50"
            type="text"
            placeholder="000000"
          />
        </label>

        <p v-if="errorMessage" class="mt-4 rounded-2xl border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {{ errorMessage }}
        </p>

        <p
          v-if="successMessage"
          class="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200"
        >
          {{ successMessage }}
        </p>

        <button
          class="mt-6 w-full rounded-2xl bg-gradient-to-r from-red-500 to-orange-400 px-4 py-3 font-semibold text-slate-950 transition hover:from-red-400 hover:to-orange-300 disabled:cursor-not-allowed disabled:opacity-70"
          :disabled="loading"
          type="submit"
        >
          {{ loading ? "Verifying..." : "Unlock Dashboard Access" }}
        </button>

        <button
          class="mt-3 w-full rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 font-semibold text-slate-200 transition hover:border-white/20 hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-60"
          :disabled="resending"
          type="button"
          @click="resendCode"
        >
          {{ resending ? "Resending..." : "Resend Verification Code" }}
        </button>

        <p class="mt-5 text-xs leading-6 text-slate-500">
          Authorized access only. This challenge is monitored and expires automatically to preserve session integrity.
        </p>
      </form>
    </section>
  </main>
</template>
