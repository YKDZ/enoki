ALTER TABLE `metric_samples` ADD `memory_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_1` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_5` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_15` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `uptime_seconds` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `disk_used_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `disk_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `network_rx_bytes_delta` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `network_tx_bytes_delta` integer;--> statement-breakpoint
CREATE TABLE `metric_cpu_cores` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`name` text NOT NULL,
	`user` integer NOT NULL,
	`nice` integer NOT NULL,
	`system` integer NOT NULL,
	`idle` integer NOT NULL,
	`iowait` integer NOT NULL,
	`irq` integer NOT NULL,
	`softirq` integer NOT NULL,
	`steal` integer NOT NULL,
	`usage_percent` real NOT NULL
);
--> statement-breakpoint
CREATE TABLE `metric_disks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`mount_point` text NOT NULL,
	`filesystem_type` text NOT NULL,
	`total_bytes` integer NOT NULL,
	`used_bytes` integer NOT NULL,
	`available_bytes` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `metric_network_interfaces` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`name` text NOT NULL,
	`rx_bytes` integer NOT NULL,
	`tx_bytes` integer NOT NULL,
	`rx_bytes_delta` integer NOT NULL,
	`tx_bytes_delta` integer NOT NULL
);
