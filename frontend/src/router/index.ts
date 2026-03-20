import { createRouter, createWebHistory } from "vue-router";

import { useAuthStore } from "@/stores/auth";
import AssetProfileView from "@/views/AssetProfileView.vue";
import DashboardView from "@/views/DashboardView.vue";
import LoginView from "@/views/LoginView.vue";
import UsersView from "@/views/UsersView.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: LoginView,
      meta: { public: true },
    },
    {
      path: "/",
      name: "dashboard",
      component: DashboardView,
    },
    {
      path: "/assets",
      name: "assets",
      component: AssetProfileView,
    },
    {
      path: "/assets/:id",
      name: "asset-profile",
      component: AssetProfileView,
    },
    {
      path: "/users",
      name: "users",
      component: UsersView,
      meta: { adminOnly: true },
    },
  ],
});

router.beforeEach((to) => {
  const authStore = useAuthStore();
  authStore.hydrateSessionFromStorage();

  if (to.meta.public) {
    if (to.name === "login" && authStore.isAuthenticated) {
      return { name: "dashboard" };
    }
    return true;
  }

  if (!authStore.isAuthenticated) {
    return { name: "login" };
  }

  if (to.meta.adminOnly && !authStore.isAdmin) {
    return { name: "dashboard" };
  }

  return true;
});

export default router;
