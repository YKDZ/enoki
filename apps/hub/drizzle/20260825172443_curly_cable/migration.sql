ALTER TABLE `enrollment_tokens` ADD `registration_attempt_sha256` text;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `registration_outcome` blob;
