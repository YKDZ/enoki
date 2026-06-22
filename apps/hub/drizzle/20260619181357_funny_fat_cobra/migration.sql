CREATE TABLE `enrollment_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`token_hash` text NOT NULL,
	`created_at_ms` integer NOT NULL,
	`expires_at_ms` integer NOT NULL,
	`used_at_ms` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_idx` ON `enrollment_tokens` (`token_hash`);