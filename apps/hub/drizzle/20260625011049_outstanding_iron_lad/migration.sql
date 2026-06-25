CREATE TABLE `audit_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`occurred_at_ms` integer NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`outcome` text NOT NULL,
	`subject_type` text,
	`subject_id` text,
	`remote_address` text,
	`user_agent` text,
	`details_json` text
);
--> statement-breakpoint
CREATE TABLE `enrollment_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`token_hash` text NOT NULL,
	`created_at_ms` integer NOT NULL,
	`expires_at_ms` integer NOT NULL,
	`used_at_ms` integer
);
--> statement-breakpoint
CREATE TABLE `managed_hosts` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`probe_id` text NOT NULL,
	`probe_secret_hash` text NOT NULL,
	`probe_public_key_pem` text,
	`display_name` text NOT NULL,
	`display_name_edited` integer NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`hostname` text,
	`os` text,
	`kernel` text,
	`architecture` text,
	`cpu_count` integer,
	`cpu_model` text,
	`memory_total_bytes` integer,
	`probe_version` text,
	`connect_address` text NOT NULL,
	`connect_address_edited` integer DEFAULT false NOT NULL,
	`observed_ip` text,
	`probe_configuration_version` text NOT NULL,
	`probe_configuration_error_failed_version` text,
	`probe_configuration_error_code` text,
	`probe_configuration_error_message` text,
	`probe_configuration_error_reported_at_ms` integer,
	`created_at_ms` integer NOT NULL,
	`deleted_at_ms` integer,
	`last_report_at_ms` integer,
	`clock_skew_detected` integer DEFAULT false NOT NULL,
	`last_clock_skew_ms` integer
);
--> statement-breakpoint
CREATE TABLE `metric_samples` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`managed_host_id` integer NOT NULL,
	`probe_id` text NOT NULL,
	`boot_id` text NOT NULL,
	`sequence` integer NOT NULL,
	`collected_at_ms` integer NOT NULL,
	`received_at_ms` integer NOT NULL,
	`cpu_percent` real,
	`cpu_user_percent` real,
	`cpu_system_percent` real,
	`cpu_iowait_percent` real,
	`cpu_steal_percent` real,
	`cpu_idle_percent` real,
	`memory_used_bytes` integer,
	`memory_total_bytes` integer,
	`memory_cache_bytes` integer,
	`swap_total_bytes` integer,
	`swap_used_bytes` integer,
	`load_1` real,
	`load_5` real,
	`load_15` real,
	`uptime_seconds` integer,
	`temperature_celsius` real,
	`battery_percent` integer,
	`battery_state` text,
	`disk_used_bytes` integer,
	`disk_total_bytes` integer,
	`network_rx_bytes_delta` integer,
	`network_tx_bytes_delta` integer,
	CONSTRAINT `fk_metric_samples_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `metrics_archive_runs` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`period` text NOT NULL,
	`range_start_ms` integer NOT NULL,
	`range_end_ms` integer NOT NULL,
	`status` text NOT NULL,
	`archive_path` text,
	`checksum_sha256` text,
	`row_counts_json` text,
	`cleanup_status` text,
	`cleanup_completed_at_ms` integer,
	`cleanup_error_message` text,
	`started_at_ms` integer NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`completed_at_ms` integer,
	`error_message` text
);
--> statement-breakpoint
CREATE TABLE `official_host_profiles` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`managed_host_id` integer NOT NULL,
	`snapshot_hash` text NOT NULL,
	`payload_json` text NOT NULL,
	`hostname` text NOT NULL,
	`os` text NOT NULL,
	`kernel` text NOT NULL,
	`architecture` text NOT NULL,
	`cpu_count` integer NOT NULL,
	`cpu_model` text,
	`memory_total_bytes` integer NOT NULL,
	`probe_version` text NOT NULL,
	`collector_capabilities_json` text,
	`filesystems_json` text NOT NULL,
	`network_interfaces_json` text NOT NULL,
	`updated_at_ms` integer NOT NULL,
	CONSTRAINT `fk_official_host_profiles_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `probe_configuration_global_defaults` (
	`id` integer PRIMARY KEY,
	`version` text NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`metrics_collection_interval_seconds` integer NOT NULL,
	`enabled_collector_ids_json` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `probe_configuration_host_overrides` (
	`managed_host_id` integer PRIMARY KEY,
	`version` text NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`metrics_collection_interval_seconds` integer NOT NULL,
	`enabled_collector_ids_json` text NOT NULL,
	CONSTRAINT `fk_probe_configuration_host_overrides_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `probe_operations` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`managed_host_id` integer NOT NULL,
	`kind` text NOT NULL,
	`state` text NOT NULL,
	`current_probe_version` text,
	`target_probe_version` text NOT NULL,
	`failure_code` text,
	`failure_message` text,
	`created_at_ms` integer NOT NULL,
	`updated_at_ms` integer NOT NULL,
	`accepted_at_ms` integer,
	`running_at_ms` integer,
	`completed_at_ms` integer,
	`superseded_at_ms` integer,
	`canceled_at_ms` integer,
	CONSTRAINT `fk_probe_operations_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `probe_request_nonces` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`probe_id` text NOT NULL,
	`nonce` text NOT NULL,
	`expires_at_ms` integer NOT NULL,
	CONSTRAINT `fk_probe_request_nonces_probe_id_managed_hosts_probe_id_fk` FOREIGN KEY (`probe_id`) REFERENCES `managed_hosts`(`probe_id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `report_observations` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`managed_host_id` integer NOT NULL,
	`probe_id` text NOT NULL,
	`boot_id` text NOT NULL,
	`sequence` integer NOT NULL,
	`received_at_ms` integer NOT NULL,
	CONSTRAINT `fk_report_observations_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_idx` ON `enrollment_tokens` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `managed_hosts_probe_id_idx` ON `managed_hosts` (`probe_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `managed_hosts_probe_secret_hash_idx` ON `managed_hosts` (`probe_secret_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `metric_samples_probe_boot_sequence_idx` ON `metric_samples` (`probe_id`,`boot_id`,`sequence`);--> statement-breakpoint
CREATE INDEX `metrics_archive_runs_status_range_idx` ON `metrics_archive_runs` (`status`,`range_start_ms`,`range_end_ms`);--> statement-breakpoint
CREATE INDEX `metrics_archive_runs_period_range_idx` ON `metrics_archive_runs` (`period`,`range_start_ms`,`range_end_ms`);--> statement-breakpoint
CREATE UNIQUE INDEX `official_host_profiles_host_idx` ON `official_host_profiles` (`managed_host_id`);--> statement-breakpoint
CREATE INDEX `official_host_profiles_snapshot_hash_idx` ON `official_host_profiles` (`snapshot_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `probe_operations_one_active_per_host_idx` ON `probe_operations` (`managed_host_id`) WHERE state in ('pending', 'accepted', 'running');--> statement-breakpoint
CREATE INDEX `probe_operations_active_for_host_idx` ON `probe_operations` (`managed_host_id`,`updated_at_ms`,`id`) WHERE state in ('pending', 'accepted', 'running');--> statement-breakpoint
CREATE INDEX `probe_operations_latest_for_host_idx` ON `probe_operations` (`managed_host_id`,`updated_at_ms`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `probe_request_nonces_probe_nonce_idx` ON `probe_request_nonces` (`probe_id`,`nonce`);--> statement-breakpoint
CREATE INDEX `probe_request_nonces_expires_at_idx` ON `probe_request_nonces` (`expires_at_ms`);--> statement-breakpoint
CREATE UNIQUE INDEX `report_observations_probe_boot_sequence_idx` ON `report_observations` (`probe_id`,`boot_id`,`sequence`);
