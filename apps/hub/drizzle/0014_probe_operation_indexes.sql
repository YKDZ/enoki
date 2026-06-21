CREATE UNIQUE INDEX `probe_operations_one_active_per_host_idx` ON `probe_operations` (`managed_host_id`) WHERE state in ('pending', 'accepted', 'running');--> statement-breakpoint
CREATE INDEX `probe_operations_active_for_host_idx` ON `probe_operations` (`managed_host_id`, `updated_at_ms`, `id`) WHERE state in ('pending', 'accepted', 'running');--> statement-breakpoint
CREATE INDEX `probe_operations_latest_for_host_idx` ON `probe_operations` (`managed_host_id`, `updated_at_ms`, `id`);
