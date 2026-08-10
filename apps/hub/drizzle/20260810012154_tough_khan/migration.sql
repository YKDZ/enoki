ALTER TABLE `enrollment_tokens` ADD `enrollment_id` text;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `target_kind` text;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `target_host_id` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `status` text DEFAULT 'expired' NOT NULL;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `managed_host_id` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `verification_deadline_at_ms` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `ready_at_ms` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `rejected_at_ms` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `expired_at_ms` integer;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `rejection_code` text;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `rejection_message` text;--> statement-breakpoint
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
	`status` text DEFAULT 'expired' NOT NULL,
	`managed_host_id` integer,
	`verification_deadline_at_ms` integer,
	`ready_at_ms` integer,
	`rejected_at_ms` integer,
	`expired_at_ms` integer,
	`rejection_code` text,
	`rejection_message` text,
	CONSTRAINT "enrollment_tokens_status_check" CHECK("status" in ('pending', 'verifying', 'ready', 'rejected', 'expired')),
	CONSTRAINT "enrollment_tokens_target_check" CHECK(("target_kind" = 'new_host' and "target_host_id" is null) or ("target_kind" = 'existing_host' and "target_host_id" > 0) or ("target_kind" is null and "target_host_id" is null and "status" = 'expired')),
	CONSTRAINT "enrollment_tokens_rejection_check" CHECK(("rejection_code" is null and "rejection_message" is null) or ("rejection_code" is not null and length("rejection_code") between 1 and 64 and ("rejection_message" is null or length("rejection_message") between 1 and 512)))
);
--> statement-breakpoint
INSERT INTO `__new_enrollment_tokens`(`id`, `token_hash`, `created_at_ms`, `expires_at_ms`, `used_at_ms`) SELECT `id`, `token_hash`, `created_at_ms`, `expires_at_ms`, `used_at_ms` FROM `enrollment_tokens`;--> statement-breakpoint
DROP TABLE `enrollment_tokens`;--> statement-breakpoint
ALTER TABLE `__new_enrollment_tokens` RENAME TO `enrollment_tokens`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_idx` ON `enrollment_tokens` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_enrollment_id_idx` ON `enrollment_tokens` (`enrollment_id`);--> statement-breakpoint
CREATE INDEX `enrollment_tokens_status_expiry_idx` ON `enrollment_tokens` (`status`,`expires_at_ms`);