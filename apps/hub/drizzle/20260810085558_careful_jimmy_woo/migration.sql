CREATE TABLE `snapshot_replay_requests` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`managed_host_id` integer NOT NULL,
	`collector_id` text NOT NULL,
	`boot_id` text DEFAULT '' NOT NULL,
	`sequence` integer DEFAULT 0 NOT NULL,
	`snapshot_hash` text DEFAULT '' NOT NULL,
	`requested_at_ms` integer NOT NULL,
	`fulfilled_at_ms` integer,
	CONSTRAINT `fk_snapshot_replay_requests_managed_host_id_managed_hosts_id_fk` FOREIGN KEY (`managed_host_id`) REFERENCES `managed_hosts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_one_active_existing_host_idx` ON `enrollment_tokens` (`target_host_id`) WHERE "enrollment_tokens"."target_kind" = 'existing_host' and "enrollment_tokens"."status" in ('pending', 'verifying');--> statement-breakpoint
CREATE UNIQUE INDEX `snapshot_replay_requests_host_collector_idx` ON `snapshot_replay_requests` (`managed_host_id`,`collector_id`);