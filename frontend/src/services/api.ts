import axios from "axios";

import { useAuthStore } from "@/stores/auth";
import router from "@/router";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api",
});

const RETRYABLE_METHODS = new Set(["get"]);
const MAX_NETWORK_RETRIES = 2;
const RETRY_DELAY_MS = 600;

function sleep(delay: number) {
  return new Promise((resolve) => window.setTimeout(resolve, delay));
}

api.interceptors.request.use((config) => {
  const authStore = useAuthStore();
  if (authStore.token) {
    config.headers.Authorization = `Bearer ${authStore.token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const requestConfig = error.config as (typeof error.config & {
      _networkRetryCount?: number;
    }) | undefined;

    if (
      requestConfig &&
      !error.response &&
      RETRYABLE_METHODS.has((requestConfig.method ?? "get").toLowerCase())
    ) {
      requestConfig._networkRetryCount = requestConfig._networkRetryCount ?? 0;

      if (requestConfig._networkRetryCount < MAX_NETWORK_RETRIES) {
        requestConfig._networkRetryCount += 1;
        await sleep(RETRY_DELAY_MS * requestConfig._networkRetryCount);
        return api.request(requestConfig);
      }
    }

    const authStore = useAuthStore();
    if (error.response?.status === 401) {
      authStore.clearSession();
      if (router.currentRoute.value.name !== "login") {
        await router.push({ name: "login" });
      }
    }
    return Promise.reject(error);
  },
);

export default api;
