<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import { Card, CardContent } from "@/components/ui/card";

import AppHeader from "./components/AppHeader.vue";
import EnrollmentDialog from "./components/EnrollmentDialog.vue";
import GlobalConfigurationPanel from "./components/GlobalConfigurationPanel.vue";
import LoginPanel from "./components/LoginPanel.vue";
import ManagedHostCard from "./components/ManagedHostCard.vue";
import ManagedHostDetailPage from "./components/ManagedHostDetailPage.vue";
import { useLiveUpdates } from "./composables/useLiveUpdates";
import { useManagedHostDetail } from "./composables/useManagedHostDetail";
import { apiGet, saveConfiguration } from "./lib/api";
import { configurationErrorText } from "./lib/probe-configuration";
import type {
  EnrollmentResponse,
  HostMetadataDraft,
  HostProbeConfigurationResponse,
  ManagedHostDetail,
  ManagedHostSummary,
  ManagedHostsResponse,
  ProbeConfiguration,
  SessionResponse,
} from "./types";

const isCheckingSession = ref(true);
const isAuthenticated = ref(false);
const isSubmitting = ref(false);
const isCreatingEnrollment = ref(false);
const isShowingEnrollmentDialog = ref(false);
const isShowingGlobalConfiguration = ref(false);
const isSavingGlobalConfiguration = ref(false);
const isSavingHostConfiguration = ref(false);
const password = ref("");
const loginError = ref("");
const hosts = ref<ManagedHostSummary[]>([]);
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
const activeDetailHostId = ref(routeManagedHostId());
const activeDetailHostIdForComposable = computed(
  () => activeDetailHostId.value ?? 0,
);
const detail = useManagedHostDetail(activeDetailHostIdForComposable);

const {
  connectLiveUpdates,
  disconnectLiveUpdates,
  subscribeManagedHostDetail,
  unsubscribeManagedHostDetail,
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
  try {
    const session = await apiGet<SessionResponse>("/api/web/auth/session");
    isAuthenticated.value = session.authenticated;

    if (session.authenticated) {
      await loadHosts();
      connectLiveUpdates();
      if (activeDetailHostId.value) {
        subscribeManagedHostDetail(activeDetailHostId.value);
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
  window.removeEventListener("popstate", syncRouteFromLocation);
});

window.addEventListener("popstate", syncRouteFromLocation);

async function login() {
  loginError.value = "";
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
      loginError.value = "管理员密码不正确，请稍后再试。";
      return;
    }

    password.value = "";
    isAuthenticated.value = true;
    await loadHosts();
    connectLiveUpdates();
    if (activeDetailHostId.value) {
      subscribeManagedHostDetail(activeDetailHostId.value);
      void detail.load();
    }
  } catch {
    loginError.value = "无法连接 Hub，请检查服务是否正在运行。";
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
  deletingHostId.value = null;
  activeDetailHostId.value = null;
  password.value = "";
  isAuthenticated.value = false;
  window.history.pushState({}, "", "/");
}

async function loadHosts() {
  const response = await apiGet<ManagedHostsResponse>("/api/web/managed-hosts");
  hosts.value = response.hosts;
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
    !enrollment.value &&
    !enrollmentError.value &&
    !isCreatingEnrollment.value
  ) {
    await createEnrollment();
  }
}

async function copyInstallCommand() {
  if (!enrollment.value) {
    return;
  }

  await navigator.clipboard.writeText(enrollment.value.installCommand);
}

async function toggleGlobalConfiguration() {
  isShowingGlobalConfiguration.value = !isShowingGlobalConfiguration.value;
  globalConfigurationMessage.value = "";

  if (isShowingGlobalConfiguration.value && !globalConfigurationDraft.value) {
    await loadGlobalConfiguration();
  }
}

async function loadGlobalConfiguration() {
  globalConfigurationError.value = "";

  try {
    const response = await apiGet<{ configuration: ProbeConfiguration }>(
      "/api/web/probe-configuration",
    );
    globalConfigurationDraft.value = { ...response.configuration };
  } catch {
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
      `/api/web/managed-hosts/${hostId}/probe-configuration`,
    );
    hostConfigurationDraft.value = {
      configuration: { ...response.configuration },
      mode: response.mode,
    };
  } catch {
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
      `/api/web/managed-hosts/${activeHostConfigurationId.value}/probe-configuration`,
      {
        body: JSON.stringify(body),
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
        },
        method: "PUT",
      },
    );

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
    ManagedHostSummary | ManagedHostDetail,
    "connectAddress" | "displayName" | "id"
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

    if (!displayName || !connectAddress) {
      throw new Error("invalid_host_metadata");
    }

    if (displayName !== hostMetadataOriginal.value.displayName) {
      metadataUpdate.displayName = displayName;
    }

    if (connectAddress !== hostMetadataOriginal.value.connectAddress) {
      metadataUpdate.connectAddress = connectAddress;
    }

    if (Object.keys(metadataUpdate).length === 0) {
      activeHostMetadataId.value = null;
      hostMetadataDraft.value = null;
      hostMetadataOriginal.value = null;
      return;
    }

    const response = await fetch(
      `/api/web/managed-hosts/${activeHostMetadataId.value}/metadata`,
      {
        body: JSON.stringify(metadataUpdate),
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
        },
        method: "PUT",
      },
    );

    if (!response.ok) {
      throw new Error(((await response.json()) as { error?: string }).error);
    }

    await loadHosts();
    if (activeDetailHostId.value) {
      await detail.load();
    }
    activeHostMetadataId.value = null;
    hostMetadataDraft.value = null;
    hostMetadataOriginal.value = null;
  } catch {
    hostMetadataError.value = "无法保存主机信息，请检查输入后重试。";
  } finally {
    isSavingHostMetadata.value = false;
  }
}

async function deleteHost(
  host: Pick<ManagedHostSummary | ManagedHostDetail, "displayName" | "id">,
) {
  deletingHostId.value = host.id;

  try {
    const response = await fetch(`/api/web/managed-hosts/${host.id}`, {
      credentials: "same-origin",
      method: "DELETE",
    });

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
  activeDetailHostId.value = hostId;
  window.history.pushState({}, "", hostDetailPath(hostId));
  subscribeManagedHostDetail(hostId);
  void detail.load();
}

function navigateToOverview() {
  if (activeDetailHostId.value) {
    unsubscribeManagedHostDetail(activeDetailHostId.value);
  }
  activeDetailHostId.value = null;
  window.history.pushState({}, "", "/");
}

function syncRouteFromLocation() {
  const nextHostId = routeManagedHostId();
  if (activeDetailHostId.value && activeDetailHostId.value !== nextHostId) {
    unsubscribeManagedHostDetail(activeDetailHostId.value);
  }
  activeDetailHostId.value = nextHostId;
  if (nextHostId) {
    subscribeManagedHostDetail(nextHostId);
    void detail.load();
  }
}

function routeManagedHostId() {
  const match = window.location.pathname.match(
    /^\/(?:hosts|managed-hosts)\/(\d+)$/,
  );
  const hostId = Number(match?.[1]);

  if (!Number.isInteger(hostId) || hostId <= 0) {
    return null;
  }

  if (window.location.pathname.startsWith("/managed-hosts/")) {
    window.history.replaceState({}, "", hostDetailPath(hostId));
  }

  return hostId;
}

function hostDetailPath(hostId: number) {
  return `/hosts/${hostId}`;
}
</script>

<template>
  <main class="bg-background text-foreground min-h-screen">
    <AppHeader
      :is-authenticated="isAuthenticated"
      :is-creating-enrollment="isCreatingEnrollment"
      @logout="logout"
      @open-enrollment="openEnrollmentDialog"
      @toggle-global-configuration="toggleGlobalConfiguration"
    />

    <EnrollmentDialog
      v-if="isAuthenticated"
      v-model:open="isShowingEnrollmentDialog"
      :enrollment="enrollment"
      :enrollment-error="enrollmentError"
      :is-creating-enrollment="isCreatingEnrollment"
      @copy-install-command="copyInstallCommand"
      @create-enrollment="createEnrollment"
    />

    <section
      v-if="isCheckingSession"
      class="mx-auto grid max-w-5xl place-items-center px-5 py-24"
      aria-live="polite"
    >
      <LoaderCircle class="text-primary size-8 animate-spin" />
    </section>

    <LoginPanel
      v-else-if="!isAuthenticated"
      v-model:password="password"
      :is-submitting="isSubmitting"
      :login-error="loginError"
      @login="login"
    />

    <ManagedHostDetailPage
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
      @save-host-configuration="saveHostConfiguration"
      @save-host-metadata="saveHostMetadata"
    />

    <section v-else class="mx-auto max-w-7xl px-6 py-8">
      <GlobalConfigurationPanel
        v-if="isShowingGlobalConfiguration"
        :draft="globalConfigurationDraft"
        :error="globalConfigurationError"
        :is-saving="isSavingGlobalConfiguration"
        :message="globalConfigurationMessage"
        @save="saveGlobalConfiguration"
      />

      <Card
        v-if="hosts.length === 0"
        class="bg-card text-card-foreground border-slate-200"
      >
        <CardContent class="p-6">
          <p class="text-muted-foreground text-sm">暂无主机。</p>
        </CardContent>
      </Card>

      <p
        v-if="hosts.length > 0 && hostMetadataError && !activeHostMetadataId"
        class="mb-4 text-sm text-red-600"
        role="alert"
      >
        {{ hostMetadataError }}
      </p>

      <div
        v-if="hosts.length > 0"
        class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
      >
        <ManagedHostCard
          v-for="host in hosts"
          :key="host.id"
          :host="host"
          @open-host-detail="openHostDetail"
        />
      </div>
    </section>
  </main>
</template>
