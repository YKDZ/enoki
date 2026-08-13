import { afterEach, describe, expect, it, vi } from "vitest";

import { createWebFeedbackCoordinator } from "./web-feedback-coordinator";

describe("Web Feedback Coordinator", () => {
  afterEach(() => vi.useRealTimers());

  it("delivers one trusted terminal result for an individually initiated upgrade", () => {
    vi.useFakeTimers();
    const delivery = recordingDelivery();
    const feedback = createWebFeedbackCoordinator({ delivery });
    feedback.trackProbeUpgrade({
      hostId: 3,
      initiation: "individual",
      operationId: 42,
    });
    feedback.submit({
      hostId: 3,
      kind: "probe-upgrade-transition",
      operationId: 42,
      state: "succeeded",
    });
    vi.runAllTimers();
    expect(delivery.deliver).toHaveBeenCalledExactlyOnceWith({
      level: "success",
      title: "探针升级完成",
    });
  });

  it("clears terminal correlation and permits a second Host to report the same outcome", () => {
    vi.useFakeTimers();
    const delivery = recordingDelivery();
    const feedback = createWebFeedbackCoordinator({
      aggregationWindowMs: 0,
      delivery,
    });
    for (const hostId of [3, 4]) {
      feedback.trackProbeUpgrade({
        hostId,
        initiation: "individual",
        operationId: 42,
      });
      feedback.submit({
        hostId,
        kind: "probe-upgrade-transition",
        operationId: 42,
        state: "succeeded",
      });
      vi.runAllTimers();
    }
    expect(delivery.deliver).toHaveBeenCalledTimes(2);
  });

  it("aggregates related feedback during one bounded flush window", () => {
    vi.useFakeTimers();
    const delivery = recordingDelivery();
    const feedback = createWebFeedbackCoordinator({
      aggregationWindowMs: 100,
      delivery,
    });
    feedback.submit({
      hostId: 1,
      kind: "host-delete-requested",
      mode: "uninstall",
    });
    feedback.submit({
      hostId: 2,
      kind: "host-delete-requested",
      mode: "uninstall",
    });
    expect(delivery.deliver).not.toHaveBeenCalled();
    vi.advanceTimersByTime(100);
    expect(delivery.deliver).toHaveBeenCalledExactlyOnceWith({
      level: "success",
      title: "已下发卸载探针并删除主机请求等 2 项",
    });
  });

  it("expires deduplication keys and evicts old correlations under a fixed capacity", () => {
    vi.useFakeTimers();
    let currentTime = 0;
    const delivery = recordingDelivery();
    const feedback = createWebFeedbackCoordinator({
      aggregationWindowMs: 0,
      correlationTtlMs: 10,
      deduplicationTtlMs: 10,
      delivery,
      maxCorrelations: 1,
      now: () => currentTime,
    });
    feedback.trackProbeUpgrade({
      hostId: 1,
      initiation: "individual",
      operationId: 1,
    });
    feedback.trackProbeUpgrade({
      hostId: 2,
      initiation: "individual",
      operationId: 2,
    });
    feedback.submit({
      hostId: 1,
      kind: "probe-upgrade-transition",
      operationId: 1,
      state: "succeeded",
    });
    feedback.submit({
      hostId: 2,
      kind: "probe-upgrade-transition",
      operationId: 2,
      state: "succeeded",
    });
    vi.runAllTimers();
    expect(delivery.deliver).toHaveBeenCalledExactlyOnceWith({
      level: "success",
      title: "探针升级完成",
    });
    currentTime = 11;
    feedback.submit({
      hostId: 9,
      kind: "clock-skew-detected",
      roundedDeltaSeconds: 1,
    });
    vi.runAllTimers();
    feedback.submit({
      hostId: 9,
      kind: "clock-skew-detected",
      roundedDeltaSeconds: 1,
    });
    vi.runAllTimers();
    expect(delivery.deliver).toHaveBeenCalledTimes(2);
  });

  it("restores the closed retry action only for an offline rejected Host", () => {
    vi.useFakeTimers();
    const retry = vi.fn();
    const delivery = recordingDelivery();
    const feedback = createWebFeedbackCoordinator({
      aggregationWindowMs: 0,
      delivery,
      onRetryHostEnrollment: retry,
    });
    feedback.submit({
      enrollmentId: "enr_1",
      hostId: 7,
      kind: "enrollment-rejected",
      reason: "existing-probe-installation",
      retryHostEnrollment: true,
    });
    vi.runAllTimers();
    const presentation = delivery.deliver.mock.calls[0]?.[0];
    expect(presentation?.action?.label).toBe("查看可重新注册主机");
    presentation?.action?.onClick();
    expect(retry).toHaveBeenCalledWith(7);
  });
});

function recordingDelivery() {
  return { deliver: vi.fn() };
}
