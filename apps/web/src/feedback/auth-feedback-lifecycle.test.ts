import { describe, expect, it, vi } from "vitest";

import { clearAuthenticatedFeedbackState } from "./auth-feedback-lifecycle";

describe("authenticated feedback lifecycle", () => {
  it("atomically invalidates monitoring and queued feedback on auth exit", () => {
    const feedback = { clear: vi.fn() };
    const monitor = { clear: vi.fn() };

    clearAuthenticatedFeedbackState({ feedback, monitor });

    expect(monitor.clear).toHaveBeenCalledOnce();
    expect(feedback.clear).toHaveBeenCalledOnce();
    expect(monitor.clear).toHaveBeenCalledBefore(feedback.clear);
  });
});
