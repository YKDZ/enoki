export type InstallationCommandConfig = {
  probeApiOrigin?: string;
};

export type InstallCommandInput = {
  enrollmentToken: string;
};

export type InstallCommandResult = {
  hubUrl: string;
  installCommand: string;
};

const probeBootstrapAcquirer = "/usr/local/bin/enoki-probe-bootstrap-acquire";
const probeBootstrapActivator = "/usr/local/bin/enoki-probe-bootstrap-activate";

export function createDefaultInstallationCommandConfig(): InstallationCommandConfig {
  return {
    probeApiOrigin: "http://localhost",
  };
}

export function renderInstallCommand(
  config: InstallationCommandConfig,
  input: InstallCommandInput,
): InstallCommandResult {
  const hubUrl = config.probeApiOrigin ?? "http://localhost";
  return {
    hubUrl,
    installCommand: [
      `ENOKI_HUB_URL=${shellQuote(hubUrl)}`,
      `ENOKI_ENROLLMENT_TOKEN=${shellQuote(input.enrollmentToken)}`,
      probeBootstrapAcquirer,
      "|",
      "sudo",
      "--",
      probeBootstrapActivator,
    ].join(" "),
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
