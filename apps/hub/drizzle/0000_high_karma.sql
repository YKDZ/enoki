CREATE TABLE `audit_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
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
