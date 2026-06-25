CREATE TABLE `metric_cpu_cores` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
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
	`usage_percent` real NOT NULL,
	CONSTRAINT `fk_metric_cpu_cores_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `metric_disks` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
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
	`weighted_io_percent` real,
	CONSTRAINT `fk_metric_disks_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `metric_network_interfaces` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`name` text NOT NULL,
	`rx_bytes` integer NOT NULL,
	`tx_bytes` integer NOT NULL,
	`rx_bytes_delta` integer NOT NULL,
	`tx_bytes_delta` integer NOT NULL,
	CONSTRAINT `fk_metric_network_interfaces_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_cpu` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`cpu_percent` real,
	`cpu_user_percent` real,
	`cpu_system_percent` real,
	`cpu_iowait_percent` real,
	`cpu_steal_percent` real,
	`cpu_idle_percent` real,
	CONSTRAINT `fk_official_metric_cpu_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_disk_health` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`device_name` text NOT NULL,
	`model` text,
	`serial_number` text,
	`passed` integer NOT NULL,
	`temperature_celsius` real,
	`power_on_hours` integer,
	`total_bytes` integer,
	`used_bytes` integer,
	`usage_mount_point` text,
	`role` text,
	CONSTRAINT `fk_official_metric_disk_health_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_disk_summary` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`disk_used_bytes` integer,
	`disk_total_bytes` integer,
	CONSTRAINT `fk_official_metric_disk_summary_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_load` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`load_1` real,
	`load_5` real,
	`load_15` real,
	CONSTRAINT `fk_official_metric_load_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_memory` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`memory_used_bytes` integer,
	`memory_total_bytes` integer,
	`memory_cache_bytes` integer,
	`swap_total_bytes` integer,
	`swap_used_bytes` integer,
	CONSTRAINT `fk_official_metric_memory_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_network_summary` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`network_rx_bytes_delta` integer,
	`network_tx_bytes_delta` integer,
	CONSTRAINT `fk_official_metric_network_summary_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_thermal_power` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`temperature_celsius` real,
	`battery_percent` integer,
	`battery_state` text,
	CONSTRAINT `fk_official_metric_thermal_power_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `official_metric_uptime` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`metric_sample_id` integer NOT NULL,
	`uptime_seconds` integer,
	CONSTRAINT `fk_official_metric_uptime_metric_sample_id_metric_samples_id_fk` FOREIGN KEY (`metric_sample_id`) REFERENCES `metric_samples`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `metric_cpu_cores_sample_idx` ON `metric_cpu_cores` (`metric_sample_id`);--> statement-breakpoint
CREATE INDEX `metric_disks_sample_idx` ON `metric_disks` (`metric_sample_id`);--> statement-breakpoint
CREATE INDEX `metric_network_interfaces_sample_idx` ON `metric_network_interfaces` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_cpu_sample_idx` ON `official_metric_cpu` (`metric_sample_id`);--> statement-breakpoint
CREATE INDEX `official_metric_disk_health_sample_idx` ON `official_metric_disk_health` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_disk_summary_sample_idx` ON `official_metric_disk_summary` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_load_sample_idx` ON `official_metric_load` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_memory_sample_idx` ON `official_metric_memory` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_network_summary_sample_idx` ON `official_metric_network_summary` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_thermal_power_sample_idx` ON `official_metric_thermal_power` (`metric_sample_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_metric_uptime_sample_idx` ON `official_metric_uptime` (`metric_sample_id`);