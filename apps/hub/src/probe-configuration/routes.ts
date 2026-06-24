import type {
  HostProbeConfigurationResponse,
  ProbeConfigurationResponse,
} from "@enoki/api-client";
import { Hono } from "hono";

import type { AuditRepository } from "../database/audit.js";
import type { HostRepository } from "../database/hosts.js";
import type { ProbeConfigurationRepository } from "../database/probe-configuration.js";
import { readJsonBody } from "../http/json.js";
import {
  parseProbeConfigurationValues,
  validateProbeConfigurationValues,
} from "./model.js";

export type ProbeConfigurationRouteServices = {
  audit?: AuditRepository;
  hosts?: HostRepository;
  now?: () => number;
  probeConfigurations: ProbeConfigurationRepository;
};

export function createProbeConfigurationRoutes(
  services: ProbeConfigurationRouteServices,
) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.get("/", (context) => {
    const response = {
      configuration: services.probeConfigurations.getGlobal(),
    } satisfies ProbeConfigurationResponse;

    return context.json(response);
  });

  routes.put("/", async (context) => {
    const body = await readJsonBody(context.req);
    if (!body.ok) {
      return configurationError("malformed_json");
    }

    const input = parseProbeConfigurationValues(body.value);

    if (!input) {
      return configurationError("invalid_probe_configuration");
    }

    const validationError = validateProbeConfigurationValues(input);
    if (validationError) {
      return configurationError(validationError);
    }

    const updatedAtMs = now();
    const configuration = services.probeConfigurations.updateGlobal(
      input,
      updatedAtMs,
    );

    services.audit?.record({
      action: "probe_configuration.global.update",
      actor: "owner",
      details: {
        version: configuration.version,
      },
      occurredAtMs: updatedAtMs,
      outcome: "success",
      subjectType: "probe_configuration",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    const response = {
      configuration,
    } satisfies ProbeConfigurationResponse;

    return context.json(response);
  });

  return routes;
}

export function createHostProbeConfigurationRoutes(
  services: ProbeConfigurationRouteServices,
) {
  const routes = new Hono();
  const now = services.now ?? Date.now;

  routes.get("/", (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return configurationError("host_not_found", 404);
    }

    if (!services.hosts?.exists(hostId)) {
      return configurationError("host_not_found", 404);
    }

    const response = services.probeConfigurations.getEffectiveForHost(
      hostId,
    ) satisfies HostProbeConfigurationResponse;

    return context.json(response);
  });

  routes.put("/", async (context) => {
    const hostId = numericHostId(context.req.param("hostId"));
    if (!hostId) {
      return configurationError("host_not_found", 404);
    }

    if (!services.hosts?.exists(hostId)) {
      return configurationError("host_not_found", 404);
    }

    const body = await readJsonBody(context.req);
    if (!body.ok) {
      return configurationError("malformed_json");
    }

    if (!body.value || typeof body.value !== "object") {
      return configurationError("invalid_probe_configuration");
    }

    const candidate = body.value as {
      configuration?: unknown;
      mode?: unknown;
    };

    if (candidate.mode === "inherit") {
      const changedAtMs = now();
      const effective = services.probeConfigurations.clearHostOverride(hostId);

      services.audit?.record({
        action: "probe_configuration.host.inherit",
        actor: "owner",
        details: {
          version: effective.configuration.version,
        },
        occurredAtMs: changedAtMs,
        outcome: "success",
        subjectId: String(hostId),
        subjectType: "host",
        userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
      });

      const response = effective satisfies HostProbeConfigurationResponse;

      return context.json(response);
    }

    if (candidate.mode !== "override") {
      return configurationError("invalid_probe_configuration_mode");
    }

    const input = parseProbeConfigurationValues(candidate.configuration);
    if (!input) {
      return configurationError("invalid_probe_configuration");
    }

    const validationError = validateProbeConfigurationValues(input);
    if (validationError) {
      return configurationError(validationError);
    }

    const changedAtMs = now();
    const effective = services.probeConfigurations.updateHostOverride(
      hostId,
      input,
      changedAtMs,
    );

    services.audit?.record({
      action: "probe_configuration.host.override",
      actor: "owner",
      details: {
        version: effective.configuration.version,
      },
      occurredAtMs: changedAtMs,
      outcome: "success",
      subjectId: String(hostId),
      subjectType: "host",
      userAgent: context.req.raw.headers.get("user-agent") ?? undefined,
    });

    const response = effective satisfies HostProbeConfigurationResponse;

    return context.json(response);
  });

  return routes;
}

function configurationError(error: string, status: 400 | 404 = 400) {
  return new Response(JSON.stringify({ error }), {
    headers: {
      "content-type": "application/json",
    },
    status,
  });
}

function numericHostId(value: string | undefined) {
  const hostId = Number(value);

  return Number.isInteger(hostId) && hostId > 0 ? hostId : null;
}
