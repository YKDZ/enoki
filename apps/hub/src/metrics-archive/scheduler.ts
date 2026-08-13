import { createNoopHubLogger, type HubLogger } from "../hub-logger.js";

export type MetricsArchiveMaintenance = () => void | Promise<void>;

export type MetricsArchiveScheduler = {
  start: () => void;
  stop: () => Promise<void>;
};

export type CreateMetricsArchiveSchedulerOptions = {
  intervalMs: number;
  logger?: HubLogger;
  maintain: MetricsArchiveMaintenance;
};

export function createMetricsArchiveScheduler(
  options: CreateMetricsArchiveSchedulerOptions,
): MetricsArchiveScheduler {
  const logger = options.logger ?? createNoopHubLogger();
  let running = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let activeRun: Promise<void> | undefined;

  const scheduleNext = () => {
    if (!running) {
      return;
    }

    timer = setTimeout(() => {
      timer = undefined;
      activeRun = runOnce().finally(() => {
        activeRun = undefined;
        scheduleNext();
      });
    }, options.intervalMs);
  };

  const runOnce = async () => {
    try {
      await options.maintain();
      logger.log({
        component: "metrics-archive",
        event: "background.completed",
        level: "info",
        outcome: "maintenance_completed",
      });
    } catch {
      logger.log({
        component: "metrics-archive",
        event: "background.failed",
        level: "error",
        outcome: "maintenance_failed",
      });
    }
  };

  return {
    start() {
      if (running) {
        return;
      }

      running = true;
      scheduleNext();
    },
    async stop() {
      running = false;
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }

      await activeRun;
    },
  };
}
