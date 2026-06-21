CREATE TABLE `probe_operations` (
  `id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  `managed_host_id` integer NOT NULL,
  `kind` text NOT NULL,
  `state` text NOT NULL,
  `current_probe_version` text,
  `target_probe_version` text NOT NULL,
  `failure_code` text,
  `failure_message` text,
  `created_at_ms` integer NOT NULL,
  `updated_at_ms` integer NOT NULL,
  `accepted_at_ms` integer,
  `running_at_ms` integer,
  `completed_at_ms` integer,
  `superseded_at_ms` integer,
  `canceled_at_ms` integer
);
