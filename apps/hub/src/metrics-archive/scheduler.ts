export type MetricsArchiveMaintenance = () => void | Promise<void>;

export type MetricsArchiveScheduler = {
  start: () => void;
  stop: () => Promise<void>;
};

export type CreateMetricsArchiveSchedulerOptions = {
  intervalMs: number;
  maintain: MetricsArchiveMaintenance;
};

export function createMetricsArchiveScheduler(
  options: CreateMetricsArchiveSchedulerOptions,
): MetricsArchiveScheduler {
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
    } catch (error) {
      console.error("Metrics Archive maintenance failed.", error);
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
