<script setup lang="ts">
import type { EnrollmentTarget } from "@enoki/api-client";
import {
  LayoutGrid,
  List,
  LoaderCircle,
  Plus,
  Server,
  ServerCrash,
} from "@lucide/vue";
import { useColorMode, useEventListener, useStorage } from "@vueuse/core";
import { ConfigProvider } from "reka-ui";
import {
  computed,
  defineAsyncComponent,
  nextTick,
  onBeforeUnmount,
  onMounted,
  provide,
  ref,
  watch,
} from "vue";

import AppHeader from "./components/AppHeader.vue";
import type { DeleteHostMode } from "./components/DeleteHostAlertDialog.vue";
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
import ProbeUpgradeAllDialog from "./components/ProbeUpgradeAllDialog.vue";
import StateHero from "./components/StateHero.vue";
import { Button } from "./components/ui/button";
import { useHostDetail } from "./composables/useHostDetail";
import { useLiveUpdates } from "./composables/useLiveUpdates";
import { useProbeUpgradeMonitor } from "./composables/useProbeUpgradeMonitor";
import { clearAuthenticatedFeedbackState } from "./feedback/auth-feedback-lifecycle";
import {
  createSonnerFeedbackDelivery,
  Toaster,
} from "./feedback/sonner-feedback-adapter";
import { createWebFeedbackCoordinator } from "./feedback/web-feedback-coordinator";
import { webFeedbackKey } from "./feedback/web-feedback-port";
import {
  apiGet,
  apiMutate,
  isUnauthorizedError,
  saveConfiguration,
} from "./lib/api";
import {
  matchingHostAction,
  reconcileEnrollmentStatus,
  shouldCreateEnrollmentOnOpen,
} from "./lib/enrollment-dialog-state";
import { createEnrollmentStatusReconciler } from "./lib/enrollment-status-reconciliation";
import {
  hubUnavailableLoginError,
  loginErrorForResponse,
  type LoginErrorKind,
} from "./lib/login-errors";
import { configurationErrorText } from "./lib/probe-configuration";
import {
  matchesActiveReadyEnrollment,
  readyEnrollmentCompletion,
} from "./lib/ready-enrollment-flow";
import { locateReadyHost } from "./lib/ready-host-reveal";
import type {
  EnrollmentResponse,
  EnrollmentStatusResponse,
  HostMetadataDraft,
  HostMetadataResponse,
  HostProbeConfigurationResponse,
  HostDetail,
  HostSummary,
  HostsResponse,
  ProbeConfiguration,
  ProbeConfigurationResponse,
  ProbeUpgradeAllResponse,
  SessionResponse,
} from "./types";

const isCheckingSession = ref(true);
const webFeedback = createWebFeedbackCoordinator({
  delivery: createSonnerFeedbackDelivery(),
  onRetryHostEnrollment(hostId) {
    void createExistingHostEnrollment(hostId);
  },
});
provide(webFeedbackKey, webFeedback);
const scrollBodyLock = { margin: 0, padding: 0 } as const;
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
const isProbeUpgradeAllDialogOpen = ref(false);
const isSubmittingProbeUpgradeAll = ref(false);
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
const highlightedReadyHostId = ref<number | null>(null);
const isLoadingMoreHostCards = ref(false);
const hostListPageSizeOptions = [10, 20, 50, 100];
let hostCardLazyLoadTimer: ReturnType<typeof setTimeout> | null = null;
let readyHostHighlightTimer: ReturnType<typeof setTimeout> | null = null;
let probeUpgradeAllAttemptId = 0;
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
const enrollmentStatusReconciler = createEnrollmentStatusReconciler({
  getActiveEnrollment: () => enrollment.value,
  getActiveEnrollmentId: () => enrollment.value?.enrollmentId ?? null,
  isActiveEnrollment: (enrollmentId) =>
    isShowingEnrollmentDialog.value &&
    enrollment.value?.enrollmentId === enrollmentId &&
    ["pending", "verifying"].includes(enrollment.value.status),
  onStatus(status) {
    void applyAuthoritativeEnrollmentStatus(status);
  },
  onTemporaryFailure(error) {
    handleUnauthorizedError(error);
  },
  readStatus: (enrollmentId) =>
    apiGet<EnrollmentStatusResponse>(`/api/web/enrollments/${enrollmentId}`),
});
const hostListPageCount = computed(() =>
  Math.max(1, Math.ceil(hosts.value.length / hostListPageSize.value)),
);
const detail = useHostDetail(activeDetailHostIdForComposable, {
  onUnauthorized: requireLogin,
});
const probeUpgradeMonitor = useProbeUpgradeMonitor({
  onHostDetail(host) {
    detail.applyHostDetail(host);
  },
  onTransition(host, status) {
    webFeedback.submit({
      hostId: host.id,
      kind: "probe-upgrade-transition",
      operationId: status.id,
      state: status.state,
    });
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
  onHostProfile(hostId, hostProfile) {
    detail.applyHostProfile(hostId, hostProfile);
  },
  onHostReady(hint) {
    void handleHostReadyHint(hint);
  },
  onHostRemoved(hostId) {
    if (activeHostConfigurationId.value === hostId) {
      activeHostConfigurationId.value = null;
      hostConfigurationDraft.value = null;
    }
    if (activeHostMetadataId.value === hostId) {
      activeHostMetadataId.value = null;
      hostMetadataDraft.value = null;
      hostMetadataOriginal.value = null;
    }
    if (activeDetailHostId.value === hostId) {
      navigateToOverview();
    }
  },
  onSummary(summary) {
    detail.applyLiveSummary(summary);
  },
  recoverDetail() {
    return detail.load();
  },
  recoverEnrollment() {
    return reconcileActiveEnrollment();
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
  clearReadyHostHighlight();
  clearEnrollmentStatusReconciliation();
  webFeedback.clear();
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
  clearAuthenticatedFeedbackState({
    feedback: webFeedback,
    monitor: probeUpgradeMonitor,
  });
  await fetch("/api/web/auth/logout", {
    body: JSON.stringify({}),
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    method: "POST",
  });

  hosts.value = [];
  enrollment.value = null;
  enrollmentError.value = "";
  isShowingEnrollmentDialog.value = false;
  clearEnrollmentStatusReconciliation();
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
  clearAuthenticatedFeedbackState({
    feedback: webFeedback,
    monitor: probeUpgradeMonitor,
  });
  isAuthenticated.value = false;
  loginError.value = "";
  loginErrorKind.value = "";
  hostListError.value = "";
  enrollmentError.value = "";
  clearEnrollmentStatusReconciliation();
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

async function submitProbeUpgradeAll() {
  const attemptId = ++probeUpgradeAllAttemptId;
  isSubmittingProbeUpgradeAll.value = true;
  try {
    const summary = await apiMutate<unknown>(
      "/api/web/hosts/probe-upgrade-requests",
      { body: {}, method: "POST" },
    );
    if (!isProbeUpgradeAllResponse(summary)) {
      throw new Error("invalid_probe_upgrade_all_response");
    }
    isProbeUpgradeAllDialogOpen.value = false;
    webFeedback.submit({
      ...summary,
      attemptId,
      kind: "probe-upgrade-all-submitted",
    });
    await loadHosts();
  } catch (error) {
    if (!handleUnauthorizedError(error)) {
      webFeedback.submit({
        attemptId,
        kind: "probe-upgrade-all-request-failed",
      });
    }
  } finally {
    isSubmittingProbeUpgradeAll.value = false;
  }
}

function isProbeUpgradeAllResponse(
  value: unknown,
): value is ProbeUpgradeAllResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const response = value as Partial<ProbeUpgradeAllResponse>;
  return [response.submitted, response.skipped, response.failed].every(
    (count) =>
      typeof count === "number" && Number.isSafeInteger(count) && count >= 0,
  );
}

async function createEnrollment() {
  isShowingEnrollmentDialog.value = true;
  enrollmentError.value = "";
  isCreatingEnrollment.value = true;

  try {
    const response = await fetch("/api/web/enrollments", {
      body: JSON.stringify({}),
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
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
    scheduleEnrollmentStatusReconciliation();
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

function updateEnrollmentDialogOpen(open: boolean) {
  isShowingEnrollmentDialog.value = open;

  if (!open) {
    clearEnrollmentStatusReconciliation();
  }
}

function scheduleEnrollmentStatusReconciliation() {
  enrollmentStatusReconciler.start();
}

function clearEnrollmentStatusReconciliation() {
  enrollmentStatusReconciler.stop();
}

async function reconcileActiveEnrollment() {
  await enrollmentStatusReconciler.reconcileNow();
}

async function handleHostReadyHint(hint: {
  enrollmentId: string;
  hostId: number;
}) {
  if (
    !matchesActiveReadyEnrollment({
      activeEnrollmentId: enrollment.value?.enrollmentId,
      hintEnrollmentId: hint.enrollmentId,
      isDialogOpen: isShowingEnrollmentDialog.value,
    })
  ) {
    return;
  }

  try {
    const status = await apiGet<EnrollmentStatusResponse>(
      `/api/web/enrollments/${hint.enrollmentId}`,
    );
    if (status.status !== "ready" || status.hostId !== hint.hostId) {
      return;
    }
    await applyAuthoritativeEnrollmentStatus(status);
  } catch (error) {
    handleUnauthorizedError(error);
  }
}

async function applyAuthoritativeEnrollmentStatus(
  status: EnrollmentStatusResponse,
) {
  const reconciled = reconcileEnrollmentStatus(enrollment.value, status);
  enrollment.value = reconciled.enrollment;

  if (!reconciled.shouldClose) {
    return;
  }

  isShowingEnrollmentDialog.value = false;
  clearEnrollmentStatusReconciliation();
  if (status.status === "ready") {
    const completion = readyEnrollmentCompletion(
      status,
      activeDetailHostId.value,
    );
    if (completion.returnToOverview) {
      navigateToOverview();
    }
    if (completion.reloadHosts) {
      await loadHosts();
      if (status.hostId) {
        await revealReadyHost(status.hostId);
      }
    }
    webFeedback.submit({
      enrollmentId: status.enrollmentId,
      kind: "enrollment-ready",
    });
    return;
  }
  if (status.status === "expired") {
    webFeedback.submit({
      enrollmentId: status.enrollmentId,
      kind: "enrollment-expired",
    });
    return;
  }
  if (status.status === "rejected") {
    webFeedback.submit({
      enrollmentId: status.enrollmentId,
      hostId: status.hostId,
      kind: "enrollment-rejected",
      reason: enrollmentRejectionReason(status.rejection?.code),
      retryHostEnrollment:
        matchingHostAction({ hostId: status.hostId, hosts: hosts.value }) !==
        null,
    });
  }
}

async function createExistingHostEnrollment(hostId: number) {
  try {
    const target = {
      hostId,
      kind: "existing_host",
    } satisfies EnrollmentTarget;
    const response = await fetch("/api/web/enrollments", {
      body: JSON.stringify({ target }),
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    if (handleUnauthorizedResponse(response)) return;
    if (!response.ok) {
      showExistingHostEnrollmentFailure(
        hostId,
        await responseErrorCode(response),
      );
      return;
    }
    enrollment.value = (await response.json()) as EnrollmentResponse;
    enrollmentError.value = "";
    isShowingEnrollmentDialog.value = true;
    scheduleEnrollmentStatusReconciliation();
  } catch {
    showExistingHostEnrollmentFailure(hostId, null);
  }
}

async function createManualReinstallEnrollment(hostId: number) {
  try {
    const response = await fetch(
      `/api/web/enrollments/manual-reinstall/${hostId}`,
      {
        credentials: "same-origin",
        method: "POST",
      },
    );
    if (handleUnauthorizedResponse(response)) return;
    if (!response.ok) {
      showExistingHostEnrollmentFailure(
        hostId,
        await responseErrorCode(response),
      );
      return;
    }
    enrollment.value = (await response.json()) as EnrollmentResponse;
    enrollmentError.value = "";
    isShowingEnrollmentDialog.value = true;
    scheduleEnrollmentStatusReconciliation();
  } catch {
    showExistingHostEnrollmentFailure(hostId, null);
  }
}

async function responseErrorCode(response: Response) {
  try {
    const body = (await response.json()) as { error?: unknown } | null;
    return typeof body?.error === "string" ? body.error : null;
  } catch {
    return null;
  }
}

function showExistingHostEnrollmentFailure(
  hostId: number,
  errorCode: string | null,
) {
  webFeedback.submit({
    hostId,
    kind: "host-enrollment-retryable-failure",
    reason: enrollmentRetryFailureReason(errorCode),
  });
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
    const response = await apiGet<ProbeConfigurationResponse>(
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
  const targetHostId = activeHostMetadataId.value;

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

    const response = await fetch(`/api/web/hosts/${targetHostId}/metadata`, {
      body: JSON.stringify(metadataUpdate),
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
      },
      method: "PUT",
    });

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      throw new Error(((await response.json()) as { error?: string }).error);
    }

    const metadata = (await response.json()) as HostMetadataResponse;
    applyHostMetadataUpdate(targetHostId, metadata);

    if (activeHostMetadataId.value === targetHostId) {
      activeHostMetadataId.value = null;
      hostMetadataDraft.value = null;
      hostMetadataOriginal.value = null;
    }
    if (activeHostConfigurationId.value === targetHostId) {
      activeHostConfigurationId.value = null;
      hostConfigurationDraft.value = null;
    }
    void loadHosts();
  } catch {
    hostMetadataError.value = "无法保存主机元数据，请检查输入后重试。";
  } finally {
    isSavingHostMetadata.value = false;
  }
}

function applyHostMetadataUpdate(
  targetHostId: number,
  metadata: HostMetadataDraft,
) {
  hosts.value = hosts.value.map((host) =>
    host.id === targetHostId
      ? {
          ...host,
          connectAddress: metadata.connectAddress,
          description: metadata.description,
          displayName: metadata.displayName,
        }
      : host,
  );

  const currentHost = detail.host.value;
  if (!currentHost || currentHost.id !== targetHostId) {
    return;
  }

  detail.applyHostDetail({
    ...currentHost,
    connectAddress: metadata.connectAddress,
    description: metadata.description,
    displayName: metadata.displayName,
    hostMetadata: {
      ...currentHost.hostMetadata,
      connectAddress: metadata.connectAddress,
      description: metadata.description,
      displayName: metadata.displayName,
    },
  });
}

async function deleteHost(
  host: Pick<HostSummary | HostDetail, "displayName" | "id">,
  mode: DeleteHostMode = "uninstall",
) {
  deletingHostId.value = host.id;

  try {
    const deleteUrl =
      mode === "hub-only"
        ? `/api/web/hosts/${host.id}?mode=hub-only`
        : `/api/web/hosts/${host.id}`;
    const response = await fetch(deleteUrl, {
      credentials: "same-origin",
      method: "DELETE",
    });

    if (handleUnauthorizedResponse(response)) {
      return;
    }

    if (!response.ok) {
      throw new Error("delete_failed");
    }

    webFeedback.submit({
      hostId: host.id,
      kind: "host-delete-requested",
      mode,
    });

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
  webFeedback.trackProbeUpgrade({
    hostId,
    initiation: "individual",
    operationId: status.id,
  });
  probeUpgradeMonitor.track(hostId, status);
}

function enrollmentRejectionReason(code: string | undefined) {
  switch (code) {
    case "existing_probe_installation":
      return "existing-probe-installation" as const;
    case "probe_bound_to_different_hub":
      return "probe-bound-to-different-hub" as const;
    case "probe_installation_metadata_invalid":
      return "installation-metadata-invalid" as const;
    default:
      return "unclassified" as const;
  }
}

function enrollmentRetryFailureReason(errorCode: string | null) {
  switch (errorCode) {
    case "existing_host_reenrollment_verifying":
      return "verifying" as const;
    case "existing_host_reenrollment_unavailable":
      return "unavailable" as const;
    default:
      return "unclassified" as const;
  }
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

async function revealReadyHost(hostId: number) {
  const location = locateReadyHost({
    cardBatchSize: hostCardBatchSize,
    currentCardVisibleCount: hostCardVisibleCount.value,
    hosts: hosts.value,
    hostId,
    listPageSize: hostListPageSize.value,
    listSortDirection: hostListSortDirection.value,
    listSortKey: hostListSortKey.value,
    overviewView: overviewView.value,
  });
  if (!location) {
    return;
  }

  if (location.cardVisibleCount !== null) {
    hostCardVisibleCount.value = location.cardVisibleCount;
  }
  if (location.listPage !== null) {
    hostListPage.value = location.listPage;
  }
  highlightedReadyHostId.value = hostId;
  clearReadyHostHighlight();
  await nextTick();

  const target = document.querySelector<HTMLElement>(
    `[data-enoki-host-id="${hostId}"]`,
  );
  if (!target) {
    highlightedReadyHostId.value = null;
    return;
  }
  const reducedMotion = window.matchMedia?.(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  target.scrollIntoView({
    behavior: reducedMotion ? "auto" : "smooth",
    block: "center",
  });
  target.focus({ preventScroll: true });
  readyHostHighlightTimer = setTimeout(() => {
    highlightedReadyHostId.value = null;
    readyHostHighlightTimer = null;
  }, 2_500);
}

function clearReadyHostHighlight() {
  if (!readyHostHighlightTimer) {
    return;
  }
  clearTimeout(readyHostHighlightTimer);
  readyHostHighlightTimer = null;
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
  <ConfigProvider :scroll-body="scrollBodyLock">
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
        :open="isShowingEnrollmentDialog"
        :enrollment="enrollment"
        :enrollment-error="enrollmentError"
        :is-creating-enrollment="isCreatingEnrollment"
        @create-enrollment="createEnrollment"
        @update:open="updateEnrollmentDialogOpen"
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
        @replacement-migration-requested="createManualReinstallEnrollment"
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
          class="mb-4 flex justify-end gap-2"
        >
          <ProbeUpgradeAllDialog
            v-model:open="isProbeUpgradeAllDialogOpen"
            :is-submitting="isSubmittingProbeUpgradeAll"
            @confirm="submitProbeUpgradeAll"
          />
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
            :highlighted-host-id="highlightedReadyHostId"
            :page="hostListPage"
            :page-size="hostListPageSize"
            @create-existing-host-enrollment="createExistingHostEnrollment"
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
          :highlighted-host-id="highlightedReadyHostId"
          :is-loading-more="isLoadingMoreHostCards"
          :skeleton-count="hostCardBatchSize"
          :visible-count="hostCardVisibleCount"
          @create-existing-host-enrollment="createExistingHostEnrollment"
          @load-more="loadMoreHostCards"
          @open-host-detail="openHostDetail"
        />
      </section>
    </main>
  </ConfigProvider>
</template>
