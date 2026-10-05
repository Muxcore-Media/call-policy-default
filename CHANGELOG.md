# Changelog

## [0.3.8] - 2026-10-05

### Changed
- Built on core v0.6.14 / sdk/go/module v0.6.4: unregisters on shutdown and re-registers after core restarts (ADR-0022).

## [0.3.7] - 2026-10-05


### Changed
- Reported version comes from muxcore.json (ADR-0021); built on core v0.6.12 / sdk/go/module v0.6.3 (mesh enrollment, ADR-0017).

## [0.3.6] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

## [0.3.6] — 2026-09-05

### Added

- Inbound gRPC TLS by default (`grpc.Creds`); auto-generated mesh-local certs when none configured.
- Default bind address `127.0.0.1:9101` (was `:9101`); `MUXCORE_INSECURE_DISABLE_TLS` / `MUXCORE_GRPC_INSECURE` retain plaintext dev escape hatch.

## [0.3.5] — 2026-08-20

### Fixed

- `media-scanner` storage ACL includes `read` so `ImportPath` can List/Get `storage://torrent/…/files/` objects (mesh-backed torrents).

## [0.3.4] — 2026-08-20

### Added

- Allow `downloader-native-torrent` storage read/write (mesh piece I/O).
- Allow `indexer-torznab`, `indexer-piratebay`, and `indexer-mux` storage read/write (`.torrent` / metadata cache).

## [0.3.3] — 2026-08-10

### Added

- Advertise `settings` capability so admin-ui discovers SettingsProvider without ListAll probing.

## [0.3.1] — 2026-08-10

### Fixed
- Sync Info()/muxcore.json version to **0.3.1**.

## [0.3.0] — 2026-08-10

### Added

- Dynamic policy via event bus: subscribe to `call.policy.grant` / `call.policy.revoke`
  - Grant payload: `{id, caller, target, methods[], ttl_seconds}`
  - Revoke by `id` or caller/target match
  - TTL expiry; grants survive SIGHUP static reload

## [0.2.0] — 2026-08-09

### Added

- Policy groups (`groups` + `caller_group`)
- Per-rule `rate_limit_per_min`
- Time windows (`after` / `before` HH:MM) and `days` (mon..sun)
- Document form `{ groups, rules }` alongside legacy rule-list YAML

## [0.1.1]

### Changed

- Core pin / CI updates

## [0.1.0]

### Added

- Static YAML call policy with SIGHUP reload
