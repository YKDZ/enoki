CREATE TABLE `metric_collector_outcomes` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`collector_id` text NOT NULL,
	`state` integer NOT NULL,
	`failure_phase` integer,
	`failure_code` integer,
	CONSTRAINT `fk_metric_collector_outcomes_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `metric_collector_outcomes_sample_collector_idx` ON `metric_collector_outcomes` (`metric_sample_id`,`collector_id`);