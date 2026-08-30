ALTER TABLE `probe_operations` ADD `target_asset_set_digest` text;
--> statement-breakpoint
UPDATE `probe_operations`
SET
	`state` = 'failed',
	`failure_code` = 'probe_upgrade_target_unavailable',
	`failure_message` = 'Probe Upgrade Request predates its required Probe Asset Set target.',
	`completed_at_ms` = max(`updated_at_ms`, unixepoch() * 1000),
	`updated_at_ms` = max(`updated_at_ms`, unixepoch() * 1000)
WHERE
	`kind` = 'probe_upgrade'
	AND `target_asset_set_digest` IS NULL
	AND `state` IN ('pending', 'accepted', 'running');
