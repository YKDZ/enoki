<script setup lang="ts">
import {
  LayoutGrid,
  List,
  LoaderCircle,
  Plus,
  Server,
  ServerCrash,
} from "@lucide/vue";
import { useColorMode, useEventListener, useStorage } from "@vueuse/core";
import {
  computed,
  defineAsyncComponent,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from "vue";

import AppHeader from "./components/AppHeader.vue";
import EnrollmentDialog from "./components/EnrollmentDialog.vue";
import GlobalConfigurationDialog from "./components/GlobalConfigurationDialog.vue";
import HostCardMasonry from "./components/HostCardMasonry.vue";
import HostDetailPage from "./components/HostDetailPage.vue";
import HostDetailSkeleton from "./components/HostDetailSkeleton.vue";
import HostGridSkeleton from "./components/HostGridSkeleton.vue";
import HostListSkeleton from "./components/HostListSkeleton.vue";
import HostListView, {
  type HostListSortDirection,
  type HostListSortKey,
} from "./components/HostListView.vue";
import LoginPanel from "./components/LoginPanel.vue";
import OverviewPagination from "./components/OverviewPagination.vue";
import StateHero from "./components/StateHero.vue";
import { Button } from "./components/ui/button";
import { Toaster, toast } from "./components/ui/sonner";
import { useHostDetail } from "./composables/useHostDetail";
import { useLiveUpdates } from "./composables/useLiveUpdates";
import { useProbeUpgradeMonitor } from "./composables/useProbeUpgradeMonitor";
import { apiGet, isUnauthorizedError, saveConfiguration } from "./lib/api";
import { shouldCreateEnrollmentOnOpen } from "./lib/enrollment-dialog-state";
import {
  hubUnavailableLoginError,
  loginErrorForResponse,
  type LoginErrorKind,
} from "./lib/login-errors";
import { configurationErrorText } from "./lib/probe-configuration";
import type {
  EnrollmentResponse,
  HostMetadataDraft,
  HostProbeConfigurationResponse,
  HostDetail,
  HostSummary,
  HostsResponse,
  ProbeConfiguration,
  SessionResponse,
} from "./types";

const isCheckingSession = ref(true);
const isAuthenticated = ref(false);
const LayoutLabPage = defineAsyncComponent(
  () => import("./components/LayoutLabPage.vue"),
);
const isLayoutLabEnabled =
  import.meta.env.DEV || import.meta.env.VITE_ENABLE_LAYOUT_LAB === "1";
const isLayoutLabRoute = ref(
  isLayoutLabEnabled && routePath() === "/layout-lab",
);
const isSubmitting = ref(false);
const isCreatingEnrollment = ref(false);
const isLoadingHosts = ref(false);
const isShowingEnrollmentDialog = ref(false);
const isShowingGlobalConfiguration = ref(false);
const isSavingGlobalConfiguration = ref(false);
const isSavingHostConfiguration = ref(false);
const password = ref("");
const loginError = ref("");
const loginErrorKind = ref<LoginErrorKind>("");
const hostListError = ref("");
const hosts = ref<HostSummary[]>([]);
const overviewView = useStorage<"cards" | "list">(
  "enoki-overview-view",
  "cards",
);
const hostListSortKey = useStorage<HostListSortKey | null>(
  "enoki-overview-list-sort-key",
  null,
);
const hostListSortDirection = useStorage<HostListSortDirection>(
  "enoki-overview-list-sort-direction",
  "asc",
);
const hostCardBatchSize = 12;
const hostListPage = useStorage("enoki-overview-list-page", 1);
const hostListPageSize = useStorage("enoki-overview-list-page-size", 10);
const hostCardVisibleCount = ref(12);
const isLoadingMoreHostCards = ref(false);
const hostListPageSizeOptions = [10, 20, 50, 100];
let hostCardLazyLoadTimer: ReturnType<typeof setTimeout> | null = null;
const enrollment = ref<EnrollmentResponse | null>(null);
const enrollmentError = ref("");
const globalConfigurationDraft = ref<ProbeConfiguration | null>(null);
const globalConfigurationError = ref("");
const globalConfigurationMessage = ref("");
const activeHostConfigurationId = ref<number | null>(null);
const hostConfigurationDraft = ref<HostProbeConfigurationResponse | null>(null);
const hostConfigurationError = ref("");
const activeHostMetadataId = ref<number | null>(null);
const hostMetadataDraft = ref<HostMetadataDraft | null>(null);
const hostMetadataOriginal = ref<HostMetadataDraft | null>(null);
const hostMetadataError = ref("");
const isSavingHostMetadata = ref(false);
const deletingHostId = ref<number | null>(null);
const activeDetailHostId = ref(routeHostId());
const activeDetailHostIdForComposable = computed(
  () => activeDetailHostId.value ?? 0,
);
const themeMode = useColorMode({
  initialValue: "auto",
  modes: {
    auto: "",
    dark: "dark",
    light: "",
  },
  storageKey: "enoki-theme-mode",
});
const sonnerTheme = computed(() => {
  if (themeMode.store.value === "dark") {
    return "dark";
  }

  if (themeMode.store.value === "light") {
    return "light";
  }

  return "system";
});
const hostListPageCount = computed(() =>
  Math.max(1, Math.ceil(hosts.value.length / hostListPageSize.value)),
);
const detail = useHostDetail(activeDetailHostIdForComposable, {
  onUnauthorized: requireLogin,
});
const probeUpgradeMonitor = useProbeUpgradeMonitor({
  onFailure(failure) {
    toast.error("探针升级失败", {
      description: failure.message || failure.code,
    });
  },
  onHostDetail(host) {
    detail.applyHostDetail(host);
  },
  onSuccess() {
    toast.success("探针升级完成");
  },
  onUnauthorized: requireLogin,
});

const {
  connectLiveUpdates,
  disconnectLiveUpdates,
  subscribeHostDetail,
  unsubscribeHostDetail,
} = useLiveUpdates({
  hosts,
  isAuthenticated,
  loadHosts,
  onDetailSample(sample) {
    detail.appendLiveSample(sample);
  },
  onSummary(summary) {
    detail.applyLiveSummary(summary);
  },
  recoverDetail() {
    return detail.load();
  },
});

onMounted(async () => {
  if (isLayoutLabRoute.value) {
    isCheckingSession.value = false;
    return;
  }

  try {
    const session = await apiGet<SessionResponse>("/api/web/auth/session");
    isAuthenticated.value = session.authenticated;

    if (session.authenticated) {
      await loadHosts();
      connectLiveUpdates();
      if (activeDetailHostId.value) {
        subscribeHostDetail(activeDetailHostId.value);
        void detail.load();
      }
    }
  } catch {
    isAuthenticated.value = false;
  } finally {
    isCheckingSession.value = false;
  }
});

onBeforeUnmount(() => {
  disconnectLiveUpdates();
  clearHostCardLazyLoadTimer();
});

useEventListener("popstate", syncRouteFromLocation);

watch(
  [() => hosts.value.length, hostListPage, hostListPageSize],
  () => {
    normalizeHostListPagination();
  },
  { immediate: true },
);

watch(
  [() => hosts.value.length, hostCardVisibleCount],
  () => {
    normalizeHostCardLazyLoading();
  },
  { immediate: true },
);

async function login() {
  loginError.value = "";
  loginErrorKind.value = "";
  isSubmitting.value = true;

  try {
    const response = await fetch("/api/web/auth/login", {
      body: JSON.stringify({
        password: password.value,
      }),
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
    });

    if (!response.ok) {
      const error = loginErrorForResponse(response.status);
      loginError.value = error.message;
      loginErrorKind.value = error.kind;
      return;
    }

    password.value = "";
    isAuthenticated.value = true;
    await loadHosts();
    connectLiveUpdates();
    if (activeDetailHostId.value) {
      subscribeHostDetail(activeDetailHostId.value);
      void detail.load();
    }
  } catch {
    const error = hubUnavailableLoginError();
    loginError.value = error.message;
    loginErrorKind.value = error.kind;
  } finally {
    isSubmitting.value = false;
  }
}

async function logout() {
  disconnectLiveUpdates();
  await fetch("/api/web/auth/logout", {
    credentials: "same-origin",
    method: "POST",
  });

  hosts.value = [];
  enrollment.value = null;
  enrollmentError.value = "";
  isShowingEnrollmentDialog.value = false;
  globalConfigurationDraft.value = null;
  globalConfigurationError.value = "";
  globalConfigurationMessage.value = "";
  hostConfigurationDraft.value = null;
  hostConfigurationError.value = "";
  activeHostConfigurationId.value = null;
  activeHostMetadataId.value = null;
  hostMetadataDraft.value = null;
  hostMetadataOriginal.value = null;
  hostMetadataError.value = "";
  hostListError.value = "";
  deletingHostId.value = null;
  activeDetailHostId.value = null;
  password.value = "";
  loginErrorKind.value = "";
  isAuthenticated.value = false;
  isLayoutLabRoute.value = false;
  window.history.pushState({}, "", "/");
}

function requireLogin() {
  disconnectLiveUpdates();
  isAuthenticated.value = false;
  loginError.value = "";
  loginErrorKind.value = "";
  hostListError.value = "";
  enrollmentError.value = "";
  globalConfigurationError.value = "";
  hostConfigurationError.value = "";
  hostMetadataError.value = "";
  isShowingEnrollmentDialog.value = false;
  isShowingGlobalConfiguration.value = false;
  activeHostConfigurationId.value = null;
  hostConfigurationDraft.value = null;
  activeHostMetadataId.value = null;
  hostMetadataDraft.value = null;
  hostMetadataOriginal.value = null;
  deletingHostId.value = null;
}

function handleUnauthorizedError(error: unknown) {
  if (!isUnauthorizedError(error)) {
    return false;
  }

  requireLogin();
  return true;
}

function handleUnauthorizedResponse(response: Response) {
  if (response.status !== 401) {
    return false;
  }

  requireLogin();
  return true;
}

async function loadHosts() {
  isLoadingHosts.value = true;
  hostListError.value = "";

  try {
    const response = await apiGet<HostsResponse>("/api/web/hosts");
    hosts.value = response.hosts;
  } catch (error) {
    if (handleUnauthorizedError(error)) {
      return;
    }

    hostListError.value = "无法读取主机列表，请检查 Hub 是否正在运行。";
  } finally {
    isLoadingHosts.value = false;
  }
}

async function createEnrollment() {
  isShowingEnrollmentDialog.value = true;
  enrollmentError.value = "";
  isCreatingEnrollment.value = true;

  try {
    const response = await fetch("/api/web/enrollments", {
      credentials: "same-origin",
      method: "POST",
    });

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      enrollmentError.value = "无法创建注册令牌，请稍后再试。";
      return;
    }

    enrollment.value = (await response.json()) as EnrollmentResponse;
    await loadHosts();
  } catch {
    enrollmentError.value = "无法连接 Hub，请检查服务是否正在运行。";
  } finally {
    isCreatingEnrollment.value = false;
  }
}

async function openEnrollmentDialog() {
  isShowingEnrollmentDialog.value = true;

  if (
    shouldCreateEnrollmentOnOpen({
      enrollment: enrollment.value,
      enrollmentError: enrollmentError.value,
      isCreatingEnrollment: isCreatingEnrollment.value,
    })
  ) {
    await createEnrollment();
  }
}

async function toggleGlobalConfiguration() {
  isShowingGlobalConfiguration.value = !isShowingGlobalConfiguration.value;
  globalConfigurationMessage.value = "";

  if (!isShowingGlobalConfiguration.value) {
    return;
  }

  if (!globalConfigurationDraft.value) {
    await loadGlobalConfiguration();
  }
}

function updateGlobalConfigurationOpen(open: boolean) {
  isShowingGlobalConfiguration.value = open;

  if (open) {
    globalConfigurationMessage.value = "";
    if (!globalConfigurationDraft.value) {
      void loadGlobalConfiguration();
    }
  }
}

async function loadGlobalConfiguration() {
  globalConfigurationError.value = "";

  try {
    const response = await apiGet<{ configuration: ProbeConfiguration }>(
      "/api/web/probe-configuration",
    );
    globalConfigurationDraft.value = { ...response.configuration };
  } catch (error) {
    if (handleUnauthorizedError(error)) {
      return;
    }

    globalConfigurationError.value = "无法读取全局探针配置。";
  }
}

async function saveGlobalConfiguration() {
  if (!globalConfigurationDraft.value) {
    return;
  }

  globalConfigurationError.value = "";
  globalConfigurationMessage.value = "";
  isSavingGlobalConfiguration.value = true;

  try {
    const response = await saveConfiguration(
      "/api/web/probe-configuration",
      globalConfigurationDraft.value,
    );
    globalConfigurationDraft.value = { ...response.configuration };
    globalConfigurationMessage.value = "全局探针配置已保存。";
    await loadHosts();
  } catch (error) {
    if (handleUnauthorizedError(error)) {
      return;
    }

    globalConfigurationError.value = configurationErrorText(error);
  } finally {
    isSavingGlobalConfiguration.value = false;
  }
}

async function openHostConfiguration(hostId: number) {
  hostConfigurationError.value = "";

  if (activeHostConfigurationId.value === hostId) {
    activeHostConfigurationId.value = null;
    hostConfigurationDraft.value = null;
    return;
  }

  activeHostConfigurationId.value = hostId;

  try {
    const response = await apiGet<HostProbeConfigurationResponse>(
      `/api/web/hosts/${hostId}/probe-configuration`,
    );
    hostConfigurationDraft.value = {
      configuration: { ...response.configuration },
      mode: response.mode,
    };
  } catch (error) {
    if (handleUnauthorizedError(error)) {
      return;
    }

    hostConfigurationError.value = "无法读取此主机的探针配置。";
  }
}

async function saveHostConfiguration() {
  if (!activeHostConfigurationId.value || !hostConfigurationDraft.value) {
    return;
  }

  hostConfigurationError.value = "";
  isSavingHostConfiguration.value = true;

  try {
    const body =
      hostConfigurationDraft.value.mode === "inherit"
        ? { mode: "inherit" }
        : {
            configuration: hostConfigurationDraft.value.configuration,
            mode: "override",
          };
    const response = await fetch(
      `/api/web/hosts/${activeHostConfigurationId.value}/probe-configuration`,
      {
        body: JSON.stringify(body),
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
        },
        method: "PUT",
      },
    );

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      throw new Error(((await response.json()) as { error?: string }).error);
    }

    hostConfigurationDraft.value =
      (await response.json()) as HostProbeConfigurationResponse;
    await loadHosts();
    if (activeDetailHostId.value) {
      await detail.load();
    }
    activeHostConfigurationId.value = null;
    hostConfigurationDraft.value = null;
  } catch (error) {
    hostConfigurationError.value = configurationErrorText(error);
  } finally {
    isSavingHostConfiguration.value = false;
  }
}

function openHostMetadata(
  host: Pick<
    HostSummary | HostDetail,
    "connectAddress" | "description" | "displayName" | "id"
  >,
) {
  hostMetadataError.value = "";

  if (activeHostMetadataId.value === host.id) {
    activeHostMetadataId.value = null;
    hostMetadataDraft.value = null;
    hostMetadataOriginal.value = null;
    return;
  }

  activeHostMetadataId.value = host.id;
  hostMetadataDraft.value = {
    connectAddress: host.connectAddress,
    description: host.description,
    displayName: host.displayName,
  };
  hostMetadataOriginal.value = { ...hostMetadataDraft.value };
}

async function saveHostMetadata() {
  if (
    !activeHostMetadataId.value ||
    !hostMetadataDraft.value ||
    !hostMetadataOriginal.value
  ) {
    return;
  }

  hostMetadataError.value = "";
  isSavingHostMetadata.value = true;

  try {
    const metadataUpdate: Partial<HostMetadataDraft> = {};
    const displayName = hostMetadataDraft.value.displayName.trim();
    const connectAddress = hostMetadataDraft.value.connectAddress.trim();
    const description = hostMetadataDraft.value.description.trim();

    if (!displayName || !connectAddress) {
      throw new Error("invalid_host_metadata");
    }

    if (displayName !== hostMetadataOriginal.value.displayName) {
      metadataUpdate.displayName = displayName;
    }

    if (connectAddress !== hostMetadataOriginal.value.connectAddress) {
      metadataUpdate.connectAddress = connectAddress;
    }

    if (description !== hostMetadataOriginal.value.description) {
      metadataUpdate.description = description;
    }

    if (Object.keys(metadataUpdate).length === 0) {
      activeHostMetadataId.value = null;
      hostMetadataDraft.value = null;
      hostMetadataOriginal.value = null;
      return;
    }

    const response = await fetch(
      `/api/web/hosts/${activeHostMetadataId.value}/metadata`,
      {
        body: JSON.stringify(metadataUpdate),
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
        },
        method: "PUT",
      },
    );

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      throw new Error(((await response.json()) as { error?: string }).error);
    }

    activeHostMetadataId.value = null;
    hostMetadataDraft.value = null;
    hostMetadataOriginal.value = null;
    void loadHosts();
    if (activeDetailHostId.value) {
      void detail.load();
    }
  } catch {
    hostMetadataError.value = "无法保存主机信息，请检查输入后重试。";
  } finally {
    isSavingHostMetadata.value = false;
  }
}

async function deleteHost(
  host: Pick<HostSummary | HostDetail, "displayName" | "id">,
) {
  deletingHostId.value = host.id;

  try {
    const response = await fetch(`/api/web/hosts/${host.id}`, {
      credentials: "same-origin",
      method: "DELETE",
    });

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      throw new Error("delete_failed");
    }

    if (activeHostConfigurationId.value === host.id) {
      activeHostConfigurationId.value = null;
      hostConfigurationDraft.value = null;
    }
    if (activeHostMetadataId.value === host.id) {
      activeHostMetadataId.value = null;
      hostMetadataDraft.value = null;
      hostMetadataOriginal.value = null;
    }
    if (activeDetailHostId.value === host.id) {
      navigateToOverview();
    }
    await loadHosts();
  } catch {
    hostMetadataError.value = "无法删除主机，请稍后重试。";
  } finally {
    deletingHostId.value = null;
  }
}

function openHostDetail(hostId: number) {
  isLayoutLabRoute.value = false;
  if (activeDetailHostId.value && activeDetailHostId.value !== hostId) {
    unsubscribeHostDetail(activeDetailHostId.value);
  }
  activeDetailHostId.value = hostId;
  window.history.pushState({}, "", hostDetailPath(hostId));
  subscribeHostDetail(hostId);
  void detail.load();
}

function trackProbeUpgradeRequest(
  hostId: number,
  status: NonNullable<HostDetail["probeUpgradeStatus"]>,
) {
  probeUpgradeMonitor.track(hostId, status);
}

function navigateToOverview() {
  isLayoutLabRoute.value = false;
  if (activeDetailHostId.value) {
    unsubscribeHostDetail(activeDetailHostId.value);
  }
  activeDetailHostId.value = null;
  window.history.pushState({}, "", "/");
}

function syncRouteFromLocation() {
  isLayoutLabRoute.value = isLayoutLabEnabled && routePath() === "/layout-lab";

  if (isLayoutLabRoute.value) {
    if (activeDetailHostId.value) {
      unsubscribeHostDetail(activeDetailHostId.value);
    }
    activeDetailHostId.value = null;
    return;
  }

  const nextHostId = routeHostId();
  if (activeDetailHostId.value && activeDetailHostId.value !== nextHostId) {
    unsubscribeHostDetail(activeDetailHostId.value);
  }
  activeDetailHostId.value = nextHostId;
  if (nextHostId) {
    subscribeHostDetail(nextHostId);
    void detail.load();
  }
}

function routeHostId() {
  const match = routePath().match(/^\/hosts\/(\d+)$/);
  const hostId = Number(match?.[1]);

  if (!Number.isInteger(hostId) || hostId <= 0) {
    return null;
  }

  return hostId;
}

function hostDetailPath(hostId: number) {
  return `/hosts/${hostId}`;
}

function toggleOverviewView() {
  overviewView.value = overviewView.value === "cards" ? "list" : "cards";
}

function updateHostListPageSize(pageSize: number) {
  hostListPageSize.value = pageSize;
  hostListPage.value = 1;
  normalizeHostListPagination();
}

function loadMoreHostCards() {
  if (
    isLoadingMoreHostCards.value ||
    hostCardVisibleCount.value >= hosts.value.length
  ) {
    return;
  }

  isLoadingMoreHostCards.value = true;
  clearHostCardLazyLoadTimer();
  hostCardLazyLoadTimer = setTimeout(() => {
    hostCardVisibleCount.value = Math.min(
      hosts.value.length,
      hostCardVisibleCount.value + hostCardBatchSize,
    );
    isLoadingMoreHostCards.value = false;
    hostCardLazyLoadTimer = null;
  }, 180);
}

function normalizeHostListPagination() {
  hostListPageSize.value = normalizeOption(
    hostListPageSize.value,
    hostListPageSizeOptions,
    10,
  );

  if (hosts.value.length === 0) {
    return;
  }

  hostListPage.value = clampInteger(
    hostListPage.value,
    1,
    hostListPageCount.value,
  );
}

function normalizeHostCardLazyLoading() {
  hostCardVisibleCount.value = clampInteger(
    hostCardVisibleCount.value,
    Math.min(hostCardBatchSize, Math.max(hosts.value.length, 1)),
    Math.max(hostCardBatchSize, hosts.value.length),
  );

  if (hostCardVisibleCount.value >= hosts.value.length) {
    isLoadingMoreHostCards.value = false;
    clearHostCardLazyLoadTimer();
  }
}

function clearHostCardLazyLoadTimer() {
  if (!hostCardLazyLoadTimer) {
    return;
  }

  clearTimeout(hostCardLazyLoadTimer);
  hostCardLazyLoadTimer = null;
}

function normalizeOption(value: number, options: number[], fallback: number) {
  return options.includes(value) ? value : fallback;
}

function clampInteger(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) {
    return min;
  }

  return Math.min(Math.max(Math.trunc(value), min), max);
}

function routePath() {
  if (typeof window === "undefined") {
    return "/";
  }

  return window.location.pathname;
}
</script>

<template>
  <main class="bg-background text-foreground min-h-screen">
    <Toaster :theme="sonnerTheme" />
    <AppHeader
      :is-authenticated="isAuthenticated"
      :is-creating-enrollment="isCreatingEnrollment"
      @go-home="navigateToOverview"
      @logout="logout"
      @open-enrollment="openEnrollmentDialog"
      @toggle-global-configuration="toggleGlobalConfiguration"
    />

    <GlobalConfigurationDialog
      v-if="isAuthenticated"
      :draft="globalConfigurationDraft"
      :error="globalConfigurationError"
      :is-saving="isSavingGlobalConfiguration"
      :message="globalConfigurationMessage"
      :open="isShowingGlobalConfiguration"
      @save-probe-configuration="saveGlobalConfiguration"
      @update:open="updateGlobalConfigurationOpen"
    />

    <EnrollmentDialog
      v-if="isAuthenticated"
      v-model:open="isShowingEnrollmentDialog"
      :enrollment="enrollment"
      :enrollment-error="enrollmentError"
      :is-creating-enrollment="isCreatingEnrollment"
      @create-enrollment="createEnrollment"
    />

    <LayoutLabPage v-if="isLayoutLabRoute" />

    <section
      v-else-if="isCheckingSession"
      class="mx-auto max-w-7xl px-6 py-8"
      aria-live="polite"
    >
      <HostDetailSkeleton v-if="activeDetailHostId" />
      <HostListSkeleton v-else-if="overviewView === 'list'" />
      <HostGridSkeleton v-else />
    </section>

    <LoginPanel
      v-else-if="!isAuthenticated"
      v-model:password="password"
      :is-submitting="isSubmitting"
      :login-error="loginError"
      :login-error-kind="loginErrorKind"
      @login="login"
    />

    <HostDetailPage
      v-else-if="activeDetailHostId"
      :active-host-configuration-id="activeHostConfigurationId"
      :active-host-metadata-id="activeHostMetadataId"
      :deleting-host-id="deletingHostId"
      :detail="detail"
      :host-configuration-draft="hostConfigurationDraft"
      :host-configuration-error="hostConfigurationError"
      :host-metadata-draft="hostMetadataDraft"
      :host-metadata-error="hostMetadataError"
      :is-saving-host-configuration="isSavingHostConfiguration"
      :is-saving-host-metadata="isSavingHostMetadata"
      @back="navigateToOverview"
      @delete-host="deleteHost"
      @open-host-configuration="openHostConfiguration"
      @open-host-metadata="openHostMetadata"
      @probe-upgrade-requested="trackProbeUpgradeRequest"
      @save-host-configuration="saveHostConfiguration"
      @save-host-metadata="saveHostMetadata"
    />

    <section v-else class="mx-auto max-w-7xl px-6 py-8">
      <HostListSkeleton
        v-if="isLoadingHosts && hosts.length === 0 && overviewView === 'list'"
      />
      <HostGridSkeleton v-else-if="isLoadingHosts && hosts.length === 0" />

      <StateHero
        v-else-if="hostListError && hosts.length === 0"
        :icon="ServerCrash"
        tone="destructive"
        title="无法加载主机"
        :description="hostListError"
      >
        <template #action>
          <Button type="button" @click="loadHosts">
            <LoaderCircle
              v-if="isLoadingHosts"
              class="size-4 animate-spin"
              aria-hidden="true"
            />
            重试
          </Button>
        </template>
      </StateHero>

      <StateHero
        v-else-if="hosts.length === 0"
        :icon="Server"
        title="暂无主机"
        description="创建部署链接后，在目标机器上安装并启动探针，主机会在首次上报后出现在这里。"
      >
        <template #action>
          <Button
            type="button"
            :disabled="isCreatingEnrollment"
            @click="openEnrollmentDialog"
          >
            <LoaderCircle
              v-if="isCreatingEnrollment"
              class="size-4 animate-spin"
              aria-hidden="true"
            />
            <Plus v-else class="size-4" aria-hidden="true" />
            添加主机
          </Button>
        </template>
      </StateHero>

      <p
        v-if="!isLoadingHosts && hosts.length > 0 && hostListError"
        class="mb-4 text-sm text-red-600"
        role="alert"
      >
        {{ hostListError }}
      </p>

      <p
        v-if="
          !isLoadingHosts &&
          hosts.length > 0 &&
          hostMetadataError &&
          !activeHostMetadataId
        "
        class="mb-4 text-sm text-red-600"
        role="alert"
      >
        {{ hostMetadataError }}
      </p>

      <div
        v-if="!isLoadingHosts && hosts.length > 0"
        class="mb-4 flex justify-end"
      >
        <Button
          type="button"
          variant="outline"
          size="icon"
          :aria-label="overviewView === 'cards' ? '切换到列表' : '切换到卡片'"
          :title="overviewView === 'cards' ? '切换到列表' : '切换到卡片'"
          @click="toggleOverviewView"
        >
          <List
            v-if="overviewView === 'cards'"
            class="size-4"
            aria-hidden="true"
          />
          <LayoutGrid v-else class="size-4" aria-hidden="true" />
        </Button>
      </div>

      <div
        v-if="!isLoadingHosts && hosts.length > 0 && overviewView === 'list'"
        class="grid gap-4"
      >
        <HostListView
          v-model:sort-direction="hostListSortDirection"
          v-model:sort-key="hostListSortKey"
          :hosts="hosts"
          :page="hostListPage"
          :page-size="hostListPageSize"
          @open-host-detail="openHostDetail"
        />
        <OverviewPagination
          v-model:page="hostListPage"
          :page-size="hostListPageSize"
          :page-size-options="hostListPageSizeOptions"
          :total="hosts.length"
          @update:page-size="updateHostListPageSize"
        />
      </div>

      <HostCardMasonry
        v-else-if="!isLoadingHosts && hosts.length > 0"
        :hosts="hosts"
        :is-loading-more="isLoadingMoreHostCards"
        :skeleton-count="hostCardBatchSize"
        :visible-count="hostCardVisibleCount"
        @load-more="loadMoreHostCards"
        @open-host-detail="openHostDetail"
      />
    </section>
  </main>
</template>
