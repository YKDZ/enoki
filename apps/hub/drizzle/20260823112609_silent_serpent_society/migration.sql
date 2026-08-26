ALTER TABLE `enrollment_tokens` ADD `source_probe_sha256_json` text;--> statement-breakpoint
UPDATE `enrollment_tokens`
SET `source_probe_sha256_json` = '[]',
    `status` = CASE WHEN `status` IN ('pending', 'verifying') THEN 'rejected' ELSE `status` END,
    `rejected_at_ms` = CASE WHEN `status` IN ('pending', 'verifying') THEN `created_at_ms` ELSE `rejected_at_ms` END,
    `rejection_code` = CASE WHEN `status` IN ('pending', 'verifying') THEN 'manual_reinstall_authority_invalid' ELSE `rejection_code` END,
    `rejection_message` = CASE WHEN `status` IN ('pending', 'verifying') THEN NULL ELSE `rejection_message` END
WHERE `target_kind` = 'manual_reinstall';--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_enrollment_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`enrollment_id` text,
	`token_hash` text NOT NULL,
	`created_at_ms` integer NOT NULL,
	`expires_at_ms` integer NOT NULL,
	`used_at_ms` integer,
	`target_kind` text,
	`target_host_id` integer,
	`expected_hub_origin` text,
	`expected_probe_id` text,
	`expected_probe_version` text,
	`source_probe_sha256_json` text,
	`target_asset_set_digest` text,
	`target_probe_version` text,
	`status` text DEFAULT 'expired' NOT NULL,
	`managed_host_id` integer,
	`verification_deadline_at_ms` integer,
	`ready_at_ms` integer,
	`rejected_at_ms` integer,
	`expired_at_ms` integer,
	`rejection_code` text,
	`rejection_message` text,
	CONSTRAINT "enrollment_tokens_status_check" CHECK("status" in ('pending', 'verifying', 'ready', 'rejected', 'expired')),
	CONSTRAINT "enrollment_tokens_target_check" CHECK(("target_kind" = 'new_host' and "target_host_id" is null and "expected_hub_origin" is null and "expected_probe_id" is null and "expected_probe_version" is null and "source_probe_sha256_json" is null and "target_asset_set_digest" is null and "target_probe_version" is null) or ("target_kind" = 'existing_host' and "target_host_id" > 0 and "expected_hub_origin" is null and "expected_probe_id" is null and "expected_probe_version" is null and "source_probe_sha256_json" is null and "target_asset_set_digest" is null and "target_probe_version" is null) or ("target_kind" = 'manual_reinstall' and "target_host_id" > 0 and length("expected_hub_origin") > 0 and length("expected_probe_id") > 0 and length("expected_probe_version") > 0 and length("source_probe_sha256_json") > 0 and length("target_asset_set_digest") = 71 and length("target_probe_version") > 0) or ("target_kind" is null and "target_host_id" is null and "status" = 'expired')),
	CONSTRAINT "enrollment_tokens_rejection_check" CHECK(("rejection_code" is null and "rejection_message" is null) or ("rejection_code" is not null and length("rejection_code") between 1 and 64 and ("rejection_message" is null or length("rejection_message") between 1 and 512)))
);
--> statement-breakpoint
INSERT INTO `__new_enrollment_tokens`(`id`, `enrollment_id`, `token_hash`, `created_at_ms`, `expires_at_ms`, `used_at_ms`, `target_kind`, `target_host_id`, `expected_hub_origin`, `expected_probe_id`, `expected_probe_version`, `source_probe_sha256_json`, `target_asset_set_digest`, `target_probe_version`, `status`, `managed_host_id`, `verification_deadline_at_ms`, `ready_at_ms`, `rejected_at_ms`, `expired_at_ms`, `rejection_code`, `rejection_message`) SELECT `id`, `enrollment_id`, `token_hash`, `created_at_ms`, `expires_at_ms`, `used_at_ms`, `target_kind`, `target_host_id`, `expected_hub_origin`, `expected_probe_id`, `expected_probe_version`, `source_probe_sha256_json`, `target_asset_set_digest`, `target_probe_version`, `status`, `managed_host_id`, `verification_deadline_at_ms`, `ready_at_ms`, `rejected_at_ms`, `expired_at_ms`, `rejection_code`, `rejection_message` FROM `enrollment_tokens`;--> statement-breakpoint
DROP TABLE `enrollment_tokens`;--> statement-breakpoint
ALTER TABLE `__new_enrollment_tokens` RENAME TO `enrollment_tokens`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_idx` ON `enrollment_tokens` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_enrollment_id_idx` ON `enrollment_tokens` (`enrollment_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_one_active_existing_host_idx` ON `enrollment_tokens` (`target_host_id`) WHERE "enrollment_tokens"."target_kind" in ('existing_host', 'manual_reinstall') and "enrollment_tokens"."status" in ('pending', 'verifying');--> statement-breakpoint
CREATE INDEX `enrollment_tokens_status_expiry_idx` ON `enrollment_tokens` (`status`,`expires_at_ms`);
