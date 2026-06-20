ALTER TABLE `managed_hosts` ADD `clock_skew_detected` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `last_clock_skew_ms` integer;
