# Hub-Served Probe Asset Set

The Hub serves the current Probe Asset Set, including the signed manifest,
manifest signature, signing key, installer, and target-specific Probe archives.
The signed `manifest.json` is the source of truth for the current Probe Asset
Set version. Hub image tags, archive file names, and external release tags must
not be used as version truth for Probe Upgrade eligibility.

Probe Asset Set versions and Probe versions are compared as SemVer after
normalizing an optional leading `v`. Hosts are upgradeable only when their valid
Probe version is lower than the Hub Probe Asset Set version declared by the
manifest. Equal, higher, missing, malformed, or development Probe versions are
not upgradeable and must expose a stable reason.

This supersedes ADR-0033 for runtime install and upgrade distribution. GitHub
Releases may still be used as a publishing mechanism, but running Hubs and
Probes use Hub-served Probe Asset Set URLs instead of resolving GitHub Releases
at runtime.
