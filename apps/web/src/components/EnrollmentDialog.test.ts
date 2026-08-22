// @vitest-environment happy-dom

import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { nextTick } from "vue";

import type { EnrollmentResponse } from "../types";
import EnrollmentDialog from "./EnrollmentDialog.vue";

const pendingEnrollment: EnrollmentResponse = {
  bootstrapRecipe: {
    bundleVersion: "1.2.3",
    distribution: "enoki",
    kind: "enoki-probe-bootstrap-recipe-record",
    recipe: {
      file: "enoki-probe-bootstrap.py",
      sha256: "a".repeat(64),
      size: 123,
      version: "v1",
    },
    rootFingerprint: "b".repeat(64),
    schemaVersion: 1,
    targets: ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-musl"],
  },
  createdAtMs: 1_725_000_000_000,
  enrollmentId: "enr_1234567890abcdef",
  enrollmentToken: "enk_enroll_component_test",
  expiredAtMs: null,
  expiresAtMs: 1_725_000_900_000,
  hostId: null,
  hubUrl: "https://hub.example.test",
  installCommand:
    "ENOKI_HUB_URL='https://hub.example.test' ENOKI_ENROLLMENT_TOKEN='enk_enroll_test' /usr/local/bin/enoki-probe-bootstrap-acquire | sudo -- /usr/local/bin/enoki-probe-bootstrap-activate",
  readyAtMs: null,
  rejectedAtMs: null,
  rejection: null,
  status: "pending",
  target: { kind: "new_host" },
  verificationDeadlineAtMs: null,
};

describe("Enrollment dialog command control", () => {
  afterEach(() => {
    document.body.replaceChildren();
    vi.restoreAllMocks();
  });

  it("mounts and focuses one native read-only command textarea when the command arrives", async () => {
    const focus = vi.spyOn(HTMLTextAreaElement.prototype, "focus");
    const wrapper = mount(EnrollmentDialog, {
      attachTo: document.body,
      props: dialogProps({ enrollment: null }),
    });

    await wrapper.setProps({ enrollment: pendingEnrollment });
    await flushRender();

    const command = mountedCommand();
    expect(command.value).toBe(pendingEnrollment.installCommand);
    expect(command.readOnly).toBe(true);
    expect(command.autocomplete).toBe("off");
    expect(command.getAttribute("wrap")).toBe("off");
    expect(document.activeElement).toBe(command);
    expect(focus).toHaveBeenCalled();
    const focusCallsAfterCommandArrival = focus.mock.calls.length;

    await wrapper.setProps({
      enrollment: {
        ...pendingEnrollment,
        expiresAtMs: pendingEnrollment.expiresAtMs + 1,
      },
    });
    await flushRender();

    expect(document.activeElement).toBe(command);
    expect(focus).toHaveBeenCalledTimes(focusCallsAfterCommandArrival);
    wrapper.unmount();
  });

  it("keeps native selection, input, and paste behavior scoped to the read-only textarea", async () => {
    const wrapper = mount(EnrollmentDialog, {
      attachTo: document.body,
      props: dialogProps({ enrollment: pendingEnrollment }),
    });
    await flushRender();

    const command = mountedCommand();
    command.select();
    expect(command.selectionStart).toBe(0);
    expect(command.selectionEnd).toBe(command.value.length);

    const initialValue = command.value;
    command.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        data: "mutate",
        inputType: "insertText",
      }),
    );
    command.dispatchEvent(
      new ClipboardEvent("paste", {
        bubbles: true,
        clipboardData: new DataTransfer(),
      }),
    );

    expect(command.readOnly).toBe(true);
    expect(command.value).toBe(initialValue);
    wrapper.unmount();
  });

  it("shows every exact supported target as a readable verification list", async () => {
    const wrapper = mount(EnrollmentDialog, {
      attachTo: document.body,
      props: dialogProps({ enrollment: pendingEnrollment }),
    });
    await flushRender();

    const targets = document.querySelector('[aria-label="支持的目标平台"]');
    expect(
      Array.from(targets?.querySelectorAll("li") ?? []).map((item) =>
        item.textContent?.trim(),
      ),
    ).toEqual(pendingEnrollment.bootstrapRecipe.targets);
    wrapper.unmount();
  });
});

type DialogProps = {
  enrollment: EnrollmentResponse | null;
  enrollmentError: string;
  isCreatingEnrollment: boolean;
  open: boolean;
};

function dialogProps(overrides: Partial<DialogProps>): DialogProps {
  return {
    enrollment: null,
    enrollmentError: "",
    isCreatingEnrollment: false,
    open: true,
    ...overrides,
  };
}

async function flushRender() {
  await nextTick();
  await nextTick();
}

function mountedCommand() {
  const command = document.querySelector<HTMLTextAreaElement>(
    'textarea[aria-label="安装命令"]',
  );
  if (!command) {
    throw new Error("Expected the mounted Enrollment command textarea.");
  }

  return command;
}
