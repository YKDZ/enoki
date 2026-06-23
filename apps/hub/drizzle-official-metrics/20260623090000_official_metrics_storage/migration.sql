CREATE TABLE `official_metric_cpu` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`cpu_percent` real,
	`cpu_user_percent` real,
	`cpu_system_percent` real,
	`cpu_iowait_percent` real,
	`cpu_steal_percent` real,
	`cpu_idle_percent` real
);
--> statement-breakpoint
CREATE TABLE `official_metric_memory` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`memory_used_bytes` integer,
	`memory_total_bytes` integer,
	`memory_cache_bytes` integer,
	`swap_total_bytes` integer,
	`swap_used_bytes` integer
);
--> statement-breakpoint
CREATE TABLE `official_metric_load` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`load_1` real,
	`load_5` real,
	`load_15` real
);
--> statement-breakpoint
CREATE TABLE `official_metric_uptime` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`uptime_seconds` integer
);
--> statement-breakpoint
CREATE TABLE `official_metric_thermal_power` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`temperature_celsius` real,
	`battery_percent` integer,
	`battery_state` text
);
--> statement-breakpoint
CREATE TABLE `official_metric_disk_summary` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`disk_used_bytes` integer,
	`disk_total_bytes` integer
);
--> statement-breakpoint
CREATE TABLE `official_metric_network_summary` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`network_rx_bytes_delta` integer,
	`network_tx_bytes_delta` integer
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `metric_cpu_cores` (
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
CREATE TABLE IF NOT EXISTS `metric_disks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`mount_point` text NOT NULL,
	`filesystem_type` text NOT NULL,
	`total_bytes` integer NOT NULL,
	`used_bytes` integer NOT NULL,
	`available_bytes` integer NOT NULL,
	`read_bytes_delta` integer DEFAULT 0 NOT NULL,
	`write_bytes_delta` integer DEFAULT 0 NOT NULL,
	`io_utilization_percent` real,
	`read_await_ms` real,
	`write_await_ms` real,
	`weighted_io_percent` real
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `metric_network_interfaces` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`metric_sample_id` integer NOT NULL,
	`name` text NOT NULL,
	`rx_bytes` integer NOT NULL,
	`tx_bytes` integer NOT NULL,
	`rx_bytes_delta` integer NOT NULL,
	`tx_bytes_delta` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_cpu_sample_idx` ON `official_metric_cpu` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_memory_sample_idx` ON `official_metric_memory` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_load_sample_idx` ON `official_metric_load` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_uptime_sample_idx` ON `official_metric_uptime` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_thermal_power_sample_idx` ON `official_metric_thermal_power` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_disk_summary_sample_idx` ON `official_metric_disk_summary` (`metric_sample_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_network_summary_sample_idx` ON `official_metric_network_summary` (`metric_sample_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `metric_cpu_cores_sample_idx` ON `metric_cpu_cores` (`metric_sample_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `metric_disks_sample_idx` ON `metric_disks` (`metric_sample_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `metric_network_interfaces_sample_idx` ON `metric_network_interfaces` (`metric_sample_id`);
--> statement-breakpoint
INSERT INTO `official_metric_cpu` (
	`metric_sample_id`,
	`cpu_percent`,
	`cpu_user_percent`,
	`cpu_system_percent`,
	`cpu_iowait_percent`,
	`cpu_steal_percent`,
	`cpu_idle_percent`
)
SELECT
	`id`,
	`cpu_percent`,
	`cpu_user_percent`,
	`cpu_system_percent`,
	`cpu_iowait_percent`,
	`cpu_steal_percent`,
	`cpu_idle_percent`
FROM `metric_samples`
WHERE
	`cpu_percent` IS NOT NULL
	OR `cpu_user_percent` IS NOT NULL
	OR `cpu_system_percent` IS NOT NULL
	OR `cpu_iowait_percent` IS NOT NULL
	OR `cpu_steal_percent` IS NOT NULL
	OR `cpu_idle_percent` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_memory` (
	`metric_sample_id`,
	`memory_used_bytes`,
	`memory_total_bytes`,
	`memory_cache_bytes`,
	`swap_total_bytes`,
	`swap_used_bytes`
)
SELECT
	`id`,
	`memory_used_bytes`,
	`memory_total_bytes`,
	`memory_cache_bytes`,
	`swap_total_bytes`,
	`swap_used_bytes`
FROM `metric_samples`
WHERE
	`memory_used_bytes` IS NOT NULL
	OR `memory_total_bytes` IS NOT NULL
	OR `memory_cache_bytes` IS NOT NULL
	OR `swap_total_bytes` IS NOT NULL
	OR `swap_used_bytes` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_load` (
	`metric_sample_id`,
	`load_1`,
	`load_5`,
	`load_15`
)
SELECT
	`id`,
	`load_1`,
	`load_5`,
	`load_15`
FROM `metric_samples`
WHERE `load_1` IS NOT NULL OR `load_5` IS NOT NULL OR `load_15` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_uptime` (`metric_sample_id`, `uptime_seconds`)
SELECT `id`, `uptime_seconds`
FROM `metric_samples`
WHERE `uptime_seconds` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_thermal_power` (
	`metric_sample_id`,
	`temperature_celsius`,
	`battery_percent`,
	`battery_state`
)
SELECT
	`id`,
	`temperature_celsius`,
	`battery_percent`,
	`battery_state`
FROM `metric_samples`
WHERE
	`temperature_celsius` IS NOT NULL
	OR `battery_percent` IS NOT NULL
	OR `battery_state` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_disk_summary` (
	`metric_sample_id`,
	`disk_used_bytes`,
	`disk_total_bytes`
)
SELECT `id`, `disk_used_bytes`, `disk_total_bytes`
FROM `metric_samples`
WHERE `disk_used_bytes` IS NOT NULL OR `disk_total_bytes` IS NOT NULL;
--> statement-breakpoint
INSERT INTO `official_metric_network_summary` (
	`metric_sample_id`,
	`network_rx_bytes_delta`,
	`network_tx_bytes_delta`
)
SELECT `id`, `network_rx_bytes_delta`, `network_tx_bytes_delta`
FROM `metric_samples`
WHERE
	`network_rx_bytes_delta` IS NOT NULL
	OR `network_tx_bytes_delta` IS NOT NULL;
