export type InstallationCommandConfig = {
  installPath: string;
  installScriptPath: string;
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
};

const defaultInstallPath = "/usr/local/bin/enoki-probe";
const defaultInstallScriptPath = "/api/probe/install.sh";

export function createDefaultInstallationCommandConfig(): InstallationCommandConfig {
  return {
    installPath: defaultInstallPath,
    installScriptPath: defaultInstallScriptPath,
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
  ];

  if (config.installPath !== defaultInstallPath) {
    variables.push(["ENOKI_INSTALL_PATH", config.installPath]);
  }

  const installScriptUrl = `${hubUrl}${config.installScriptPath}`;

  return {
    hubUrl,
    installCommand: [
      "curl",
      "-fsSL",
      shellQuote(installScriptUrl),
      "|",
      "sudo",
      "env",
      ...variables.map(([name, value]) => `${name}=${shellQuote(value)}`),
      "bash",
    ].join(" "),
    installPath: config.installPath,
    installScriptUrl,
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
