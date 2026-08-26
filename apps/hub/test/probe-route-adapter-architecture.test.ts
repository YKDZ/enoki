import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const routeSource = readFileSync(
  new URL("../src/probe/routes.ts", import.meta.url),
  "utf8",
);
const reportAdapterSource = readFileSync(
  new URL("../src/probe/report-reconciliation.ts", import.meta.url),
  "utf8",
);
const reportValidationSource = readFileSync(
  new URL("../src/probe/report-validation.ts", import.meta.url),
  "utf8",
);
const hostProfileSnapshotsSource = readFileSync(
  new URL("../src/probe/host-profile-snapshots.ts", import.meta.url),
  "utf8",
);

describe("Probe route Adapter architecture", () => {
  it("delegates registration and report business reconciliation across focused Module seams", () => {
    expect(routeSource).toContain('from "./registration-delivery.js"');
    expect(routeSource).toContain('from "./report-reconciliation.js"');

    expect(routeSource).not.toContain("services.enrollments.registerNewHost(");
    expect(routeSource).not.toContain("services.reportTransaction.run(");
    expect(routeSource).not.toContain('routes.post("/register"');
    expect(routeSource).not.toContain('routes.post("/report"');
    expect(routeSource).not.toContain("function validateReportEnvelope(");
    expect(routeSource).not.toContain("function reportResponsibilityFor(");
    expect(routeSource).not.toContain(
      "function registrationInstallationRejection(",
    );
  });

  it("keeps report transactions behind a Hono-free business Module", () => {
    expect(reportAdapterSource).toContain(
      'from "./report-transaction-reconciliation.js"',
    );
    expect(reportAdapterSource).not.toContain(
      "services.reportTransaction.run(",
    );
    expect(reportAdapterSource).not.toContain(
      "reconcileAuthenticatedOperationEvidence(",
    );
    expect(reportAdapterSource).not.toContain(
      "services.metrics.recordObservationSample(",
    );

    const transactionSource = readFileSync(
      new URL(
        "../src/probe/report-transaction-reconciliation.ts",
        import.meta.url,
      ),
      "utf8",
    );
    expect(transactionSource).not.toContain('from "hono"');
    expect(transactionSource).not.toContain("Context");
  });

  it("keeps canonical Host Profile snapshot identity in one Module", () => {
    expect(hostProfileSnapshotsSource).toContain('from "node:crypto"');
    expect(reportValidationSource).not.toContain('from "node:crypto"');
    expect(reportValidationSource).toContain(
      'from "./host-profile-snapshots.js"',
    );
    expect(reportValidationSource).not.toContain("function hashHostProfile(");
    expect(reportValidationSource).not.toContain("function stableHostProfile(");
  });
});
