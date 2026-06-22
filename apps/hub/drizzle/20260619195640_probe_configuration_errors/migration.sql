ALTER TABLE `managed_hosts` ADD `probe_configuration_error_failed_version` text;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `probe_configuration_error_code` text;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `probe_configuration_error_message` text;--> statement-breakpoint
ALTER TABLE `managed_hosts` ADD `probe_configuration_error_reported_at_ms` integer;
