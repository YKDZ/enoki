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
ALTER TABLE `metric_samples` ADD `battery_state` text;
