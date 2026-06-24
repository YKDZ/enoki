ALTER TABLE `official_metric_disk_health` ADD COLUMN `total_bytes` integer;
--> statement-breakpoint
ALTER TABLE `official_metric_disk_health` ADD COLUMN `used_bytes` integer;
--> statement-breakpoint
ALTER TABLE `official_metric_disk_health` ADD COLUMN `usage_mount_point` text;
--> statement-breakpoint
ALTER TABLE `official_metric_disk_health` ADD COLUMN `role` text;
