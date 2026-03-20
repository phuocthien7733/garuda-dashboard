import axios from "axios";

import { useAuthStore } from "@/stores/auth";
import router from "@/router";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
});

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
