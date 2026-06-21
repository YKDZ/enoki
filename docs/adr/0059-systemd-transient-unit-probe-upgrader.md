# systemd Transient Unit Probe Upgrader

Probe Upgrade is a Hub-controlled Probe Operation, not Probe auto-update. The
Probe service remains a non-root long-running process, and privileged upgrade
work is delegated to the Probe Upgrader internal entry point.

The Probe starts the Probe Upgrader through a constrained systemd transient unit
or equivalent isolated systemd execution path. Running the upgrader as a normal
child of the main Probe service is rejected because restarting the Probe service
could kill the upgrade process before it atomically replaces the binary and
restarts the service.

The installer grants only the minimum privilege required to start the typed Probe
Upgrader entry point. Probe Operation Tokens are passed through stdin, not
command-line arguments, and authorize one specific Probe Upgrade Request. This
keeps ADR-0017's rejection of automatic update channels while allowing an
Owner-authorized, auditable runtime Probe Upgrade path.
