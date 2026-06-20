import { createAdaptorServer } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import { createNodeWebSocket } from "@hono/node-ws";
import { Hono } from "hono";

import {
  createHubApp,
  createProbeApiApp,
  type HubAppOptions,
  type ProbeApiAppOptions,
} from "./app.js";

export type HubNodeServerOptions = HubAppOptions & {
  hostname?: string;
  port: number;
};

export type HubNodeServer = {
  address: ServerType["address"];
  close: () => Promise<void>;
};

export async function createHubNodeServer(
  options: HubNodeServerOptions,
): Promise<HubNodeServer> {
  const app = new Hono();
  const webSocket = createNodeWebSocket({ app });

  createHubApp({
    ...options,
    app,
    webSocket: {
      upgradeWebSocket: webSocket.upgradeWebSocket,
    },
  });

  const server = createAdaptorServer({
    fetch: app.fetch,
    hostname: options.hostname,
    port: options.port,
  });
  webSocket.injectWebSocket(server);

  await new Promise<void>((resolve) => {
    server.listen(options.port, options.hostname, () => {
      resolve();
    });
  });

  return {
    address: server.address.bind(server),
    close() {
      return new Promise<void>((resolve, reject) => {
        for (const client of webSocket.wss.clients) {
          client.terminate();
        }
        webSocket.wss.close();
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    },
  };
}

export type ProbeApiNodeServerOptions = ProbeApiAppOptions & {
  hostname?: string;
  port: number;
};

export async function createProbeApiNodeServer(
  options: ProbeApiNodeServerOptions,
): Promise<HubNodeServer> {
  const app = createProbeApiApp(options);
  const server = createAdaptorServer({
    fetch: app.fetch,
    hostname: options.hostname,
    port: options.port,
  });

  await new Promise<void>((resolve) => {
    server.listen(options.port, options.hostname, () => {
      resolve();
    });
  });

  return {
    address: server.address.bind(server),
    close() {
      return new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    },
  };
}
