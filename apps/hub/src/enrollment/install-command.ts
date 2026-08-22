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

const probeBootstrapRecipe = "./enoki-probe-bootstrap.py";

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
      "printf",
      "'%s\\n'",
      shellQuote(input.enrollmentToken),
      "|",
      "python3",
      "--",
      probeBootstrapRecipe,
      "--hub-origin",
      shellQuote(hubUrl),
    ].join(" "),
  };
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
