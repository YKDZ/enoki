export const manualReinstallRequired = "manual-reinstall-required";

export function resolveReleaseTransition(baseline) {
  if (baseline?.kind === "enoki-trust-epoch-migration-baseline") {
    return manualReinstallRequired;
  }
  if (baseline?.kind === "enoki-release-baseline") {
    return "in-place-upgrade";
  }
  throw new Error("Release Baseline has no authorized transition");
}

export function requiresManualReinstall(baseline) {
  return resolveReleaseTransition(baseline) === manualReinstallRequired;
}
