# Call Policy Default

Default inter-module call access control for MuxCore.

Without this module, every cross-module gRPC call is **denied by default**.
Core refuses all `mesh.Call()` requests until a module implementing
`CallPolicyProvider` registers with capability `"call.policy"`.

## How It Works

The module loads a static YAML policy (`policies.yaml`) that declares which
callers may invoke which targets and methods. The mesh client consults this
module before dispatching every `Call()`.

```
Module A calls Module B
        │
        ▼
mesh.Client.Call()
        │
        ▼
call-policy-default.AllowCall("moduleA", "moduleB", "method")
        │
        ▼
  allowed? ───yes──→ dispatch call
    │
   no
    │
    ▼
  return "call denied" error
```

## Configuration

### Policy File (`policies.yaml`)

Rules are evaluated in order; the first match wins. If no rule matches, the
call is denied. Wildcard `"*"` matches any caller, target, or method.

```yaml
# Allow module to call any method on any target
- caller: "downloader-qbittorrent"
  target: "*"
  methods: ["*"]

# Allow specific call patterns
- caller: "media-movies"
  target: "transcoder-ffmpeg"
  methods: ["Transcode", "Status"]

# Development mode: allow all (uncomment only for local use)
# - caller: "*"
#   target: "*"
#   methods: ["*"]
```

If the policy file is missing or invalid at startup, Init fails. Ship and
maintain an explicit `policies.yaml` (the repo includes a starter file).

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `CALL_POLICY_FILE` | `policies.yaml` | Path to policy YAML file |
| `CALL_POLICY_GRPC_ADDR` | `127.0.0.1:9101` | Listen address for this module's gRPC server |
| `MUXCORE_INSECURE_DISABLE_TLS` | unset | Set to `true` for plaintext gRPC (dev only; also rewrites `:port` binds to loopback) |
| `MUXCORE_GRPC_INSECURE` | unset | Alias for `MUXCORE_INSECURE_DISABLE_TLS` |
| `CALL_POLICY_TLS_CERT` / `CALL_POLICY_TLS_KEY` | auto-generated | Server TLS certificate and key (falls back to `MUXCORE_TLS_CERT` / `MUXCORE_TLS_KEY`) |
| `CALL_POLICY_TLS_CA` | auto-generated | Client CA bundle for optional mTLS (falls back to `MUXCORE_TLS_CA`) |
| `CALL_POLICY_TLS_DIR` | `~/.muxcore/tls/call-policy-default` | Directory for auto-generated dev certificates |

Mesh registration also uses the module SDK (`MUXCORE_GRPC_ADDR`,
`MUXCORE_MODULE_ID`, `--muxcore-mesh-addr`, `--muxcore-module-id`).


### Advanced rules (v0.2+)

```yaml
groups:
  media-managers:
    - media-movies
    - media-tv
rules:
  - caller_group: media-managers
    target: "transcoder-ffmpeg"
    methods: ["Transcode"]
    rate_limit_per_min: 30
    after: "08:00"
    before: "22:00"
    days: ["mon", "tue", "wed", "thu", "fri"]
```

Legacy files that are a bare YAML list of rules still work.

### Dynamic grants (v0.3+)

Modules can request temporary access at runtime by publishing mesh events:

| Event | Payload |
|-------|---------|
| `call.policy.grant` | `{"id":"optional","caller":"mod-a","target":"mod-b","methods":["Call"],"ttl_seconds":300}` |
| `call.policy.revoke` | `{"id":"optional"}` or `{"caller":"mod-a","target":"mod-b"}` |

Grants are evaluated after static YAML rules. They survive SIGHUP reloads and expire when `ttl_seconds` elapses (`0` = until revoke / process exit).

### Hot-Reload

SIGHUP reloads the policy file without restarting the module (dynamic grants are kept).

## Implementation

- Registers with capability: `"call.policy"`
- Provides `muxcore.policy.v1.PolicyService` (sidecar); core wires it as
  `contracts.CallPolicyProvider`
- Method-level control via each rule's `methods` list (including `"*"`)
- `AllowPublish` always denies — deploy `publish-policy-default` for publish policy
- Denied calls are audited by **core** at mesh enforcement (not via module `AuditLogger`); module keeps counters/`slog`
- Registers `grpc_health_v1` (SERVING) on the module gRPC server
- Tracks counters `call_policy_allowed_total` / `call_policy_denied_total`
  (`PolicyServer.Metrics()`); no HTTP metrics endpoint
