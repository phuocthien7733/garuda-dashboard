import { createRouter, createWebHistory } from "vue-router";

import { useAuthStore } from "@/stores/auth";
import AssetInventoryView from "@/views/AssetInventoryView.vue";
import AssetProfileView from "@/views/AssetProfileView.vue";
import DashboardView from "@/views/DashboardView.vue";
import HuntingMapDetailView from "@/views/HuntingMapDetailView.vue";
import HuntingMapListView from "@/views/HuntingMapListView.vue";
import LoginView from "@/views/LoginView.vue";
import MfaVerifyView from "@/views/MfaVerifyView.vue";
import UserProfileView from "@/views/UserProfileView.vue";
import UsersView from "@/views/UsersView.vue";
import VulnerabilityInventoryView from "@/views/VulnerabilityInventoryView.vue";

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
      path: "/mfa-verify",
      name: "mfa-verify",
      component: MfaVerifyView,
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
      component: AssetInventoryView,
    },
    {
      path: "/assets/:id",
      name: "asset-profile",
      component: AssetProfileView,
    },
    {
      path: "/vulnerabilities",
      name: "vulnerabilities",
      component: VulnerabilityInventoryView,
    },
    {
      path: "/hunting-maps",
      name: "hunting-maps",
      component: HuntingMapListView,
      meta: { adminOnly: true },
    },
    {
      path: "/hunting-maps/:id",
      name: "hunting-map-detail",
      component: HuntingMapDetailView,
      meta: { adminOnly: true },
    },
    {
      path: "/profile",
      name: "profile",
      component: UserProfileView,
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
    if (to.name === "mfa-verify" && !authStore.hasPendingMfaChallenge) {
      return { name: "login" };
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
