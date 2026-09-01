# Compatibility

## Core Version

Requires MuxCore v0.4.0 or later (`minCoreVersion` in `muxcore.json`).

## Capabilities

- `call.policy` — inter-module `mesh.Call` and core storage ACL enforcement
- `settings` — policy path, overlay, grantors, reload, and read-only metrics via SettingsProvider

## Contract Dependencies

- `github.com/Muxcore-Media/core/pkg/contracts` — `CallPolicyProvider` interface
- `muxcore.policy.v1.PolicyService` — `AllowCall` / `AllowPublish` gRPC
- gRPC ModuleRegistration service for sidecar registration
- gRPC DiscoveryService for module discovery (dynamic grant event subscription)

## Dynamic grants (v0.3+)

Subscribes to mesh events:

| Event | Grantor required | Payload |
|-------|------------------|---------|
| `call.policy.grant` | yes (`grantors` in YAML or `grantors` setting) | `{"id","caller","target","methods","ttl_seconds"}` |
| `call.policy.revoke` | yes | `{"id"}` or `{"caller","target"}` |

`Event.Source` must match the grantor allowlist. Grants survive SIGHUP / settings reload of static YAML.

## Storage ACL

Core `StorageService` checks `AllowCall(caller, "storage", "read"|"write")`. Shipped `policies.yaml` uses target `storage` with methods `read` and `write` (not legacy `storage-local` / `Put`/`Get`).
