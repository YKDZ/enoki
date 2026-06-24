import { randomBytes } from "node:crypto";

export type AuthEnvironment = Record<string, string | undefined>;

export type AuthConfig = {
  failureDelayMs: number;
  noPasswordWebUi?: boolean;
  ownerPassword?: string;
  publicHttps?: boolean;
  sessionCookieName: string;
  trustProxyHeaders?: boolean;
};

const defaultFailureDelayMs = 250;
const sessionCookieName = "enoki_owner_session";

export function createAuthConfigFromEnvironment(
  environment: AuthEnvironment,
): AuthConfig {
  const ownerPassword = environment.OWNER_PASSWORD;
  const noPasswordWebUi = readBoolean(environment.ENOKI_WEB_UI_NO_PASSWORD);

  if (noPasswordWebUi) {
    if (
      isProductionLike(environment) &&
      !readBoolean(environment.ENOKI_ALLOW_INSECURE_NO_PASSWORD)
    ) {
      throw new Error(
        "ENOKI_ALLOW_INSECURE_NO_PASSWORD=true is required to enable ENOKI_WEB_UI_NO_PASSWORD in production-like deployments.",
      );
    }

    console.warn(
      "ENOKI_WEB_UI_NO_PASSWORD is enabled. Enoki Web UI and management APIs are accessible without login.",
    );

    return {
      failureDelayMs: defaultFailureDelayMs,
      noPasswordWebUi: true,
      ownerPassword,
      publicHttps: readBoolean(environment.ENOKI_PUBLIC_HTTPS),
      sessionCookieName,
      trustProxyHeaders: readBoolean(environment.ENOKI_TRUST_PROXY_HEADERS),
    };
  }

  if (ownerPassword) {
    return {
      failureDelayMs: defaultFailureDelayMs,
      ownerPassword,
      publicHttps: readBoolean(environment.ENOKI_PUBLIC_HTTPS),
      sessionCookieName,
      trustProxyHeaders: readBoolean(environment.ENOKI_TRUST_PROXY_HEADERS),
    };
  }

  if (isProductionLike(environment)) {
    throw new Error(
      "OWNER_PASSWORD is required when running the Enoki Hub in production.",
    );
  }

  const temporaryPassword = randomBytes(18).toString("base64url");
  console.warn(
    `Generated temporary Enoki Owner password for development: ${temporaryPassword}`,
  );

  return {
    failureDelayMs: defaultFailureDelayMs,
    ownerPassword: temporaryPassword,
    publicHttps: readBoolean(environment.ENOKI_PUBLIC_HTTPS),
    sessionCookieName,
    trustProxyHeaders: readBoolean(environment.ENOKI_TRUST_PROXY_HEADERS),
  };
}

function isProductionLike(environment: AuthEnvironment) {
  return (
    environment.NODE_ENV === "production" ||
    environment.ENOKI_DEPLOYMENT === "docker"
  );
}

function readBoolean(value: string | undefined) {
  return value === "1" || value === "true";
}
