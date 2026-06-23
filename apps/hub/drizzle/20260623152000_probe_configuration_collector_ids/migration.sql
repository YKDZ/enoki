ALTER TABLE `probe_configuration_global_defaults` ADD COLUMN `enabled_collector_ids_json` text NOT NULL DEFAULT '["official.cpu","official.memory","official.disk","official.network","official.load","official.uptime","official.temperature","official.battery","official.disk-health"]';
--> statement-breakpoint
UPDATE `probe_configuration_global_defaults`
SET `enabled_collector_ids_json` = '[' || substr(
	CASE WHEN `collect_cpu` THEN ',"official.cpu"' ELSE '' END ||
	CASE WHEN `collect_memory` THEN ',"official.memory"' ELSE '' END ||
	CASE WHEN `collect_disk` THEN ',"official.disk"' ELSE '' END ||
	CASE WHEN `collect_network` THEN ',"official.network"' ELSE '' END ||
	CASE WHEN `collect_load` THEN ',"official.load"' ELSE '' END ||
	CASE WHEN `collect_uptime` THEN ',"official.uptime"' ELSE '' END,
	2
) || ']';
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_cpu`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_memory`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_disk`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_network`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_load`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_global_defaults` DROP COLUMN `collect_uptime`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` ADD COLUMN `enabled_collector_ids_json` text NOT NULL DEFAULT '["official.cpu","official.memory","official.disk","official.network","official.load","official.uptime","official.temperature","official.battery","official.disk-health"]';
--> statement-breakpoint
UPDATE `probe_configuration_host_overrides`
SET `enabled_collector_ids_json` = '[' || substr(
	CASE WHEN `collect_cpu` THEN ',"official.cpu"' ELSE '' END ||
	CASE WHEN `collect_memory` THEN ',"official.memory"' ELSE '' END ||
	CASE WHEN `collect_disk` THEN ',"official.disk"' ELSE '' END ||
	CASE WHEN `collect_network` THEN ',"official.network"' ELSE '' END ||
	CASE WHEN `collect_load` THEN ',"official.load"' ELSE '' END ||
	CASE WHEN `collect_uptime` THEN ',"official.uptime"' ELSE '' END,
	2
) || ']';
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_cpu`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_memory`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_disk`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_network`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_load`;
--> statement-breakpoint
ALTER TABLE `probe_configuration_host_overrides` DROP COLUMN `collect_uptime`;
