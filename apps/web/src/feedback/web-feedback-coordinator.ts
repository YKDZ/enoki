import {
  decideEnrollmentFeedback,
  type EnrollmentFeedbackFact,
} from "@/features/enrollment/enrollment-feedback-policy";
import {
  decideHostFeedback,
  type HostFeedbackFact,
} from "@/features/host/host-feedback-policy";
import {
  decideProbeUpgradeFeedback,
  type ProbeUpgradeAllRequestFailedFact,
  type ProbeUpgradeAllSubmittedFact,
  type ProbeUpgradeFeedbackInitiation,
  type ProbeUpgradeRequestFailedFact,
  type ProbeUpgradeTerminalState,
} from "@/features/probe-upgrade/probe-upgrade-feedback-policy";

import type { FeedbackAction, FeedbackDecision } from "./feedback-policy";

export type WebFeedbackFact =
  | EnrollmentFeedbackFact
  | HostFeedbackFact
  | ProbeUpgradeAllRequestFailedFact
  | ProbeUpgradeAllSubmittedFact
  | ProbeUpgradeRequestFailedFact
  | {
      hostId: number;
      kind: "probe-upgrade-transition";
      operationId: number;
      state: ProbeUpgradeTerminalState;
    };

export type FeedbackPresentation = {
  action?: { label: "重新尝试" | "查看可重新注册主机"; onClick: () => void };
  description?: string;
  level: "error" | "info" | "success" | "warning";
  title: string;
};

export type WebFeedbackDelivery = {
  deliver(presentation: FeedbackPresentation): void;
};

export type WebFeedbackCoordinator = {
  clear(): void;
  submit(fact: WebFeedbackFact): void;
  trackProbeUpgrade(correlation: {
    hostId: number;
    initiation: Exclude<ProbeUpgradeFeedbackInitiation, "untracked">;
    operationId: number;
  }): void;
};

type PendingDelivery = Extract<FeedbackDecision, { kind: "display" }> & {
  count: number;
  timer: ReturnType<typeof setTimeout>;
};

export function createWebFeedbackCoordinator(options: {
  aggregationWindowMs?: number;
  correlationTtlMs?: number;
  deduplicationTtlMs?: number;
  delivery: WebFeedbackDelivery;
  maxCorrelations?: number;
  maxDeduplicationKeys?: number;
  maxDeliveriesPerMinute?: number;
  now?: () => number;
  onRetryHostEnrollment?: (hostId: number) => void;
}): WebFeedbackCoordinator {
  const aggregationWindowMs = options.aggregationWindowMs ?? 120;
  const correlationTtlMs = options.correlationTtlMs ?? 5 * 60_000;
  const deduplicationTtlMs = options.deduplicationTtlMs ?? 60_000;
  const maxCorrelations = options.maxCorrelations ?? 128;
  const maxDeduplicationKeys = options.maxDeduplicationKeys ?? 256;
  const maxDeliveriesPerMinute = options.maxDeliveriesPerMinute ?? 6;
  const now = options.now ?? Date.now;
  const correlations = new Map<
    string,
    {
      expiresAt: number;
      initiation: Exclude<ProbeUpgradeFeedbackInitiation, "untracked">;
    }
  >();
  const deduplicationKeys = new Map<string, { expiresAt: number }>();
  const deliveryTimes: number[] = [];
  const pending = new Map<string, PendingDelivery>();

  function clear() {
    correlations.clear();
    deduplicationKeys.clear();
    deliveryTimes.length = 0;
    for (const entry of pending.values()) clearTimeout(entry.timer);
    pending.clear();
  }

  function submit(fact: WebFeedbackFact) {
    const currentTime = now();
    evictExpired(correlations, currentTime);
    evictExpired(deduplicationKeys, currentTime);
    removeExpiredDeliveryTimes(deliveryTimes, currentTime);
    const decision = decide(fact, correlations);
    if (decision.kind === "suppress") return;
    if (deduplicationKeys.has(decision.deduplicationKey)) return;
    insertBounded(
      deduplicationKeys,
      decision.deduplicationKey,
      { expiresAt: currentTime + deduplicationTtlMs },
      maxDeduplicationKeys,
    );
    enqueue(decision);
  }

  function enqueue(decision: Extract<FeedbackDecision, { kind: "display" }>) {
    const existing = pending.get(decision.aggregateKey);
    if (existing) {
      existing.count += 1;
      return;
    }
    const entry: PendingDelivery = {
      ...decision,
      count: 1,
      timer: setTimeout(
        () => flush(decision.aggregateKey),
        aggregationWindowMs,
      ),
    };
    pending.set(decision.aggregateKey, entry);
  }

  function flush(aggregateKey: string) {
    const entry = pending.get(aggregateKey);
    if (!entry) return;
    pending.delete(aggregateKey);
    const deliveredAt = now();
    removeExpiredDeliveryTimes(deliveryTimes, deliveredAt);
    if (deliveryTimes.length >= maxDeliveriesPerMinute) return;
    deliveryTimes.push(deliveredAt);
    options.delivery.deliver({
      ...(entry.description ? { description: entry.description } : {}),
      ...(presentationAction(entry.action)
        ? { action: presentationAction(entry.action) }
        : {}),
      level: entry.level,
      title:
        entry.count === 1 ? entry.title : `${entry.title}等 ${entry.count} 项`,
    });
  }

  return {
    clear,
    submit,
    trackProbeUpgrade(correlation) {
      const currentTime = now();
      evictExpired(correlations, currentTime);
      insertBounded(
        correlations,
        probeUpgradeKey(correlation.hostId, correlation.operationId),
        {
          expiresAt: currentTime + correlationTtlMs,
          initiation: correlation.initiation,
        },
        maxCorrelations,
      );
    },
  };

  function presentationAction(
    action: FeedbackAction | undefined,
  ): FeedbackPresentation["action"] {
    if (
      (action?.kind !== "retry-host-enrollment" &&
        action?.kind !== "recover-host-enrollment") ||
      !options.onRetryHostEnrollment
    ) {
      return undefined;
    }
    const retry = options.onRetryHostEnrollment;
    return {
      label:
        action.kind === "recover-host-enrollment"
          ? ("查看可重新注册主机" as const)
          : ("重新尝试" as const),
      onClick: () => retry(action.hostId),
    };
  }
}

function decide(
  fact: WebFeedbackFact,
  correlations: Map<
    string,
    {
      expiresAt: number;
      initiation: Exclude<ProbeUpgradeFeedbackInitiation, "untracked">;
    }
  >,
): FeedbackDecision {
  switch (fact.kind) {
    case "clock-skew-detected":
    case "host-delete-requested":
    case "host-enrollment-retryable-failure":
      return decideHostFeedback(fact);
    case "enrollment-expired":
    case "enrollment-ready":
    case "enrollment-rejected":
      return decideEnrollmentFeedback(fact);
    case "probe-upgrade-request-failed":
    case "probe-upgrade-all-request-failed":
    case "probe-upgrade-all-submitted":
      return decideProbeUpgradeFeedback(fact);
    case "probe-upgrade-transition": {
      const key = probeUpgradeKey(fact.hostId, fact.operationId);
      const initiation = correlations.get(key)?.initiation ?? "untracked";
      correlations.delete(key);
      return decideProbeUpgradeFeedback({
        hostId: fact.hostId,
        initiation,
        kind: "probe-upgrade-transition",
        operationId: fact.operationId,
        state: fact.state,
      });
    }
  }
}

function probeUpgradeKey(hostId: number, operationId: number) {
  return `${hostId}:${operationId}`;
}

function evictExpired<T extends { expiresAt: number }>(
  entries: Map<string, T>,
  currentTime: number,
) {
  for (const [key, entry] of entries) {
    if (entry.expiresAt <= currentTime) entries.delete(key);
  }
}

function insertBounded<T>(
  entries: Map<string, T>,
  key: string,
  value: T,
  max: number,
) {
  entries.set(key, value);
  while (entries.size > max) entries.delete(entries.keys().next().value!);
}

function removeExpiredDeliveryTimes(
  deliveryTimes: number[],
  currentTime: number,
) {
  const minuteAgo = currentTime - 60_000;
  while (deliveryTimes[0] !== undefined && deliveryTimes[0] <= minuteAgo)
    deliveryTimes.shift();
}
