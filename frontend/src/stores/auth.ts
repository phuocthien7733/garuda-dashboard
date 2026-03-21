import { computed, ref } from "vue";
import { defineStore } from "pinia";

type SessionRole = "admin" | "viewer";
type MfaChallengeState = {
  challengeId: string;
  username: string;
  maskedEmail: string;
  expiresAt: number;
};

type JwtPayload = {
  exp?: number;
  role?: string;
  sub?: string;
};

function parseJwtPayload(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const payload = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(parts[1].length / 4) * 4, "=");

    return JSON.parse(window.atob(payload)) as JwtPayload;
  } catch {
    return null;
  }
}

function isAllowedRole(role: string): role is SessionRole {
  return role === "admin" || role === "viewer";
}

export const useAuthStore = defineStore("auth", () => {
  const token = ref(localStorage.getItem("easm_token") ?? "");
  const role = ref<SessionRole>("viewer");
  const username = ref(localStorage.getItem("easm_username") ?? "");
  const expiresAt = ref<number | null>(null);
  const mfaChallenge = ref<MfaChallengeState | null>(null);

  const isAuthenticated = computed(() => {
    return Boolean(token.value) && Boolean(username.value) && !isSessionExpired();
  });

  const isAdmin = computed(() => role.value === "admin");
  const hasPendingMfaChallenge = computed(() => {
    return Boolean(mfaChallenge.value) && Date.now() < (mfaChallenge.value?.expiresAt ?? 0);
  });

  function hydrateMfaChallengeFromStorage() {
    const storedChallenge = sessionStorage.getItem("easm_mfa_challenge");
    if (!storedChallenge) {
      mfaChallenge.value = null;
      return;
    }

    try {
      const parsed = JSON.parse(storedChallenge) as MfaChallengeState;
      if (parsed.expiresAt > Date.now()) {
        mfaChallenge.value = parsed;
      } else {
        clearMfaChallenge();
      }
    } catch {
      clearMfaChallenge();
    }
  }

  function clearAuthState() {
    token.value = "";
    role.value = "viewer";
    username.value = "";
    expiresAt.value = null;
    localStorage.removeItem("easm_token");
    localStorage.removeItem("easm_role");
    localStorage.removeItem("easm_username");
  }

  function hydrateSessionFromStorage() {
    hydrateMfaChallengeFromStorage();

    const storedToken = localStorage.getItem("easm_token") ?? "";
    const storedRole = localStorage.getItem("easm_role") ?? "";
    const storedUsername = localStorage.getItem("easm_username") ?? "";

    token.value = storedToken;
    username.value = storedUsername;

    const payload = storedToken ? parseJwtPayload(storedToken) : null;
    const payloadRole = payload?.role?.toLowerCase() ?? "";
    const payloadExp = payload?.exp ? payload.exp * 1000 : null;

    role.value = isAllowedRole(payloadRole) ? payloadRole : "viewer";
    expiresAt.value = payloadExp;

    if (!storedToken || !storedUsername || !isAllowedRole(storedRole.toLowerCase()) || isSessionExpired()) {
      clearAuthState();
      return;
    }

    if (storedRole.toLowerCase() !== role.value) {
      clearAuthState();
    }
  }

  function setSession(nextToken: string, nextRole: string, nextUsername: string) {
    const payload = parseJwtPayload(nextToken);
    const normalizedRole = nextRole.toLowerCase();

    if (!payload?.exp || !isAllowedRole(normalizedRole)) {
      clearSession();
      return;
    }

    token.value = nextToken;
    role.value = normalizedRole;
    username.value = nextUsername;
    expiresAt.value = payload.exp * 1000;

    localStorage.setItem("easm_token", nextToken);
    localStorage.setItem("easm_role", normalizedRole);
    localStorage.setItem("easm_username", nextUsername);
    clearMfaChallenge();
  }

  function clearSession() {
    clearAuthState();
    clearMfaChallenge();
  }

  function isSessionExpired() {
    return expiresAt.value !== null && Date.now() >= expiresAt.value;
  }

  async function logout() {
    clearSession();
  }

  function setMfaChallenge(challengeId: string, nextUsername: string, maskedEmail: string, expiresInSeconds: number) {
    const value = {
      challengeId,
      username: nextUsername,
      maskedEmail,
      expiresAt: Date.now() + expiresInSeconds * 1000,
    };
    mfaChallenge.value = value;
    sessionStorage.setItem("easm_mfa_challenge", JSON.stringify(value));
  }

  function clearMfaChallenge() {
    mfaChallenge.value = null;
    sessionStorage.removeItem("easm_mfa_challenge");
  }

  hydrateSessionFromStorage();

  return {
    token,
    role,
    username,
    expiresAt,
    mfaChallenge,
    isAuthenticated,
    isAdmin,
    hasPendingMfaChallenge,
    hydrateSessionFromStorage,
    setSession,
    setMfaChallenge,
    clearMfaChallenge,
    clearSession,
    isSessionExpired,
    logout,
  };
});
