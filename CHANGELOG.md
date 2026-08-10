# Changelog

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
