export type InstallationCommandConfig = {
  installPath: string;
  installScriptUrl: string;
  probeDownloadUrl?: string;
  probeReleaseVersion?: string;
  publicHubUrl?: string;
};

export type InstallCommandInput = {
  enrollmentToken: string;
  requestUrl: string;
};

export type InstallCommandResult = {
  hubUrl: string;
  installCommand: string;
  installPath: string;
  installScriptUrl: string;
  probeDownloadUrl?: string;
  probeReleaseVersion?: string;
};

const defaultProbeReleaseVersion = "v0.1.0";
const defaultGitHubReleaseBaseUrl =
  "https://github.com/enoki-monitor/enoki/releases/download";
const defaultInstallPath = "/usr/local/bin/enoki-probe";

export function createDefaultInstallationCommandConfig(): InstallationCommandConfig {
  const probeReleaseVersion = defaultProbeReleaseVersion;

  return {
    installPath: defaultInstallPath,
    installScriptUrl: `${defaultGitHubReleaseBaseUrl}/${probeReleaseVersion}/install-probe.sh`,
    probeReleaseVersion,
  };
}

export function renderInstallCommand(
  config: InstallationCommandConfig,
  input: InstallCommandInput,
): InstallCommandResult {
  const hubUrl = (config.publicHubUrl ?? new URL(input.requestUrl).origin)
    .trim()
    .replace(/\/+$/, "");
  const variables: Array<[string, string]> = [
    ["ENOKI_HUB_URL", hubUrl],
    ["ENOKI_ENROLLMENT_TOKEN", input.enrollmentToken],
    ["ENOKI_INSTALL_PATH", config.installPath],
  ];

  if (config.probeDownloadUrl) {
    variables.push(["ENOKI_PROBE_DOWNLOAD_URL", config.probeDownloadUrl]);
  } else if (config.probeReleaseVersion) {
    variables.push(["ENOKI_PROBE_VERSION", config.probeReleaseVersion]);
  }

  return {
    hubUrl,
    installCommand: [
      "curl",
      "-fsSL",
      shellQuote(config.installScriptUrl),
      "|",
      "sudo",
      "env",
      ...variables.map(([name, value]) => `${name}=${shellQuote(value)}`),
      "bash",
    ].join(" "),
    installPath: config.installPath,
    installScriptUrl: config.installScriptUrl,
    probeDownloadUrl: config.probeDownloadUrl,
    probeReleaseVersion: config.probeReleaseVersion,
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
