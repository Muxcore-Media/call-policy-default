# Compatibility

## Core Version

Requires MuxCore v0.4.0 or later (`minCoreVersion` in `muxcore.json`).

## Capabilities

Registers with capability: `call.policy`

## Contract Dependencies

- `github.com/Muxcore-Media/core/pkg/contracts` — CallPolicyProvider interface
- gRPC ModuleRegistration service for sidecar registration
- gRPC DiscoveryService for module discovery
