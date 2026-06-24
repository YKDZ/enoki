CREATE TABLE `official_host_profiles` (
  `id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
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
  `updated_at_ms` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `official_host_profiles_host_idx` ON `official_host_profiles` (`managed_host_id`);
--> statement-breakpoint
CREATE INDEX `official_host_profiles_snapshot_hash_idx` ON `official_host_profiles` (`snapshot_hash`);
