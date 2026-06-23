CREATE TABLE `official_metric_disk_health` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`device_name` text NOT NULL,
	`model` text,
	`serial_number` text,
	`passed` integer NOT NULL,
	`temperature_celsius` real,
	`power_on_hours` integer
);
--> statement-breakpoint
CREATE INDEX `official_metric_disk_health_sample_idx` ON `official_metric_disk_health` (`metric_sample_id`);
