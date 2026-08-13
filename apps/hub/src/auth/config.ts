import { createNoopHubLogger, type HubLogger } from "../hub-logger.js";
import { readHttpOrigin, type TrustedProxyCidr } from "../network.js";

export type AuthEnvironment = Record<string, string | undefined>;

export type AuthConfig = {
  failureDelayMs: number;
  managementOrigin?: string;
  noPasswordWebUi?: boolean;
  ownerPassword?: string;
  sessionCookieName: string;
  trustedProxyCidrs?: TrustedProxyCidr[];
};

const defaultFailureDelayMs = 250;
const sessionCookieName = "enoki_owner_session";

export function createAuthConfigFromEnvironment(
  environment: AuthEnvironment,
  options: { logger?: HubLogger } = {},
): AuthConfig {
  const logger = options.logger ?? createNoopHubLogger();
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

    logger.log({
      component: "hub",
      event: "configuration.warning",
      level: "warn",
      outcome: "no_password_web_ui_enabled",
    });

    return {
      failureDelayMs: defaultFailureDelayMs,
      managementOrigin: readHttpOrigin(
        environment.ENOKI_MANAGEMENT_ORIGIN,
        "ENOKI_MANAGEMENT_ORIGIN",
      ),
      noPasswordWebUi: true,
      ownerPassword,
      sessionCookieName,
    };
  }

  if (ownerPassword) {
    return {
      failureDelayMs: defaultFailureDelayMs,
      managementOrigin: readHttpOrigin(
        environment.ENOKI_MANAGEMENT_ORIGIN,
        "ENOKI_MANAGEMENT_ORIGIN",
      ),
      ownerPassword,
      sessionCookieName,
    };
  }

  throw new Error(
    isProductionLike(environment)
      ? "OWNER_PASSWORD is required when running the Enoki Hub in production."
      : "OWNER_PASSWORD is required when running the Enoki Hub; set it explicitly for development.",
  );
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
