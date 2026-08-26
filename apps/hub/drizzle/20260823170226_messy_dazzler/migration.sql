ALTER TABLE `probe_operations` ADD `target_manifest_sha256` text;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `repair_authority_expires_at_ms` integer;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `repair_evidence_sha256` text;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `repair_failed_operation_id` integer;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `repair_nonce` text;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `upgrade_authority_sha256` text;--> statement-breakpoint
ALTER TABLE `probe_operations` ADD `verified_stage_sha256` text;--> statement-breakpoint
CREATE UNIQUE INDEX `probe_operations_repair_evidence_idx` ON `probe_operations` (`repair_evidence_sha256`) WHERE repair_evidence_sha256 is not null;