ALTER TABLE `metric_samples` ADD `cpu_user_percent` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `cpu_system_percent` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `cpu_iowait_percent` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `cpu_steal_percent` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `cpu_idle_percent` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `memory_cache_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `swap_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `swap_used_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `temperature_celsius` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `battery_percent` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `battery_state` text;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `read_bytes_delta` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `write_bytes_delta` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `io_utilization_percent` real;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `read_await_ms` real;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `write_await_ms` real;--> statement-breakpoint
ALTER TABLE `metric_disks` ADD `weighted_io_percent` real;
