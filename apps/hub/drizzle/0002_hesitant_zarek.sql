CREATE TABLE `managed_hosts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`probe_id` text NOT NULL,
	`probe_secret_hash` text NOT NULL,
	`display_name` text NOT NULL,
	`display_name_edited` integer NOT NULL,
	`hostname` text,
	`os` text,
	`kernel` text,
	`architecture` text,
	`probe_version` text,
	`connect_address` text NOT NULL,
	`observed_ip` text,
	`probe_configuration_version` text NOT NULL,
	`created_at_ms` integer NOT NULL,
	`last_report_at_ms` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `managed_hosts_probe_id_idx` ON `managed_hosts` (`probe_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `managed_hosts_probe_secret_hash_idx` ON `managed_hosts` (`probe_secret_hash`);