CREATE TABLE `probe_request_nonces` (
  `id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  `probe_id` text NOT NULL,
  `nonce` text NOT NULL,
  `expires_at_ms` integer NOT NULL
);--> statement-breakpoint

CREATE UNIQUE INDEX `probe_request_nonces_probe_nonce_idx` ON `probe_request_nonces` (`probe_id`, `nonce`);--> statement-breakpoint
CREATE INDEX `probe_request_nonces_expires_at_idx` ON `probe_request_nonces` (`expires_at_ms`);
