import type { HubLogger } from "./hub-logger.js";

type FatalProcess = {
  once: (
    event: "uncaughtException" | "unhandledRejection",
    listener: (reason: unknown) => void,
  ) => unknown;
};

export function createBoundedHubShutdown(options: {
  closeDatabase: () => void;
  closeListeners: () => Promise<void>;
  exit: (code: number) => void;
  logger: HubLogger;
  stopBackground: () => Promise<void>;
  timeoutMs: number;
}) {
  let active: Promise<void> | undefined;
  let requestedExitCode = 0;

  return (exitCode = 0) => {
    requestedExitCode = Math.max(requestedExitCode, exitCode);
    if (active) return active;

    options.logger.log({
      component: "hub",
      event: "process.shutdown.started",
      level: "info",
      outcome: "graceful_shutdown",
    });
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const completeShutdown = (async () => {
      await options.stopBackground();
      await options.closeListeners();
      options.closeDatabase();
    })();
    const boundedShutdown = new Promise<"timeout">((resolve) => {
      timeout = setTimeout(() => resolve("timeout"), options.timeoutMs);
    });
    active = Promise.race([
      completeShutdown.then(() => "completed" as const),
      boundedShutdown,
    ]).then(
      (result) => {
        if (timeout) clearTimeout(timeout);
        if (result === "timeout") {
          options.logger.log({
            component: "hub",
            event: "process.shutdown.completed",
            level: "error",
            outcome: "shutdown_timeout",
          });
          options.exit(1);
          return;
        }

        options.logger.log({
          component: "hub",
          event: "process.shutdown.completed",
          level: "info",
          outcome: "graceful_shutdown",
        });
        options.exit(requestedExitCode);
      },
      () => {
        if (timeout) clearTimeout(timeout);
        options.logger.log({
          component: "hub",
          event: "process.shutdown.completed",
          level: "error",
          outcome: "shutdown_failed",
        });
        options.exit(1);
      },
    );

    return active;
  };
}

export function installHubFatalHandlers(options: {
  logger: HubLogger;
  process: FatalProcess;
  shutdown: (exitCode?: number) => Promise<void>;
}) {
  let fatal = false;
  const handleFatal = (
    outcome: "startup_failure" | "uncaught_exception" | "unhandled_rejection",
    configurationMessage?: string,
  ) => {
    if (fatal) return;
    fatal = true;
    options.logger.log({
      component: "hub",
      event: "process.fatal",
      level: "error",
      outcome,
      ...(configurationMessage === undefined ? {} : { configurationMessage }),
    });
    void options.shutdown(1);
  };

  options.process.once("uncaughtException", () =>
    handleFatal("uncaught_exception"),
  );
  options.process.once("unhandledRejection", () =>
    handleFatal("unhandled_rejection"),
  );

  return handleFatal;
}
