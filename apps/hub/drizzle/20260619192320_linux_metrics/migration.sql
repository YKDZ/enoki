ALTER TABLE `metric_samples` ADD `memory_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_1` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_5` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `load_15` real;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `uptime_seconds` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `disk_used_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `disk_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `network_rx_bytes_delta` integer;--> statement-breakpoint
ALTER TABLE `metric_samples` ADD `network_tx_bytes_delta` integer;
