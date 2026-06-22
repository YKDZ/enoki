CREATE TABLE `metric_samples` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`managed_host_id` integer NOT NULL,
	`probe_id` text NOT NULL,
	`boot_id` text NOT NULL,
	`sequence` integer NOT NULL,
	`collected_at_ms` integer NOT NULL,
	`received_at_ms` integer NOT NULL,
	`cpu_percent` real,
	`memory_used_bytes` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `metric_samples_probe_boot_sequence_idx` ON `metric_samples` (`probe_id`,`boot_id`,`sequence`);--> statement-breakpoint
CREATE TABLE `report_observations` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`managed_host_id` integer NOT NULL,
	`probe_id` text NOT NULL,
	`boot_id` text NOT NULL,
	`sequence` integer NOT NULL,
	`received_at_ms` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `report_observations_probe_boot_sequence_idx` ON `report_observations` (`probe_id`,`boot_id`,`sequence`);