import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const routeSource = readFileSync(
  new URL("../src/probe/routes.ts", import.meta.url),
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
});
