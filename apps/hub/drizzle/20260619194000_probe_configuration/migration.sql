CREATE TABLE `probe_configuration_global_defaults` (
	`id` integer PRIMARY KEY NOT NULL,
	`version` text NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`metrics_collection_interval_seconds` integer NOT NULL,
	`reporting_batch_interval_seconds` integer NOT NULL,
	`collect_cpu` integer NOT NULL,
	`collect_memory` integer NOT NULL,
	`collect_disk` integer NOT NULL,
	`collect_network` integer NOT NULL,
	`collect_load` integer NOT NULL,
	`collect_uptime` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `probe_configuration_host_overrides` (
	`managed_host_id` integer PRIMARY KEY NOT NULL,
	`version` text NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`metrics_collection_interval_seconds` integer NOT NULL,
	`reporting_batch_interval_seconds` integer NOT NULL,
	`collect_cpu` integer NOT NULL,
	`collect_memory` integer NOT NULL,
	`collect_disk` integer NOT NULL,
	`collect_network` integer NOT NULL,
	`collect_load` integer NOT NULL,
	`collect_uptime` integer NOT NULL
);
