ALTER TABLE `managed_hosts` ADD `cpu_count` integer;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `memory_total_bytes` integer;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `inventory_hash` text;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `inventory_json` text;