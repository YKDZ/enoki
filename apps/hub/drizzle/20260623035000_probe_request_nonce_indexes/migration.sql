CREATE UNIQUE INDEX IF NOT EXISTS `probe_request_nonces_probe_nonce_idx` ON `probe_request_nonces` (`probe_id`, `nonce`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `probe_request_nonces_expires_at_idx` ON `probe_request_nonces` (`expires_at_ms`);
