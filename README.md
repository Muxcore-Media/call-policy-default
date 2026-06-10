# Call Policy Default

Default inter-module call access control for MuxCore.

Without this module, every cross-module gRPC call is **denied by default**.
Core refuses all `mesh.Call()` requests until a module implementing
`CallPolicyProvider` registers with capability `"call.policy"`.

## How It Works

The module provides a static policy file (`policies.yaml`) that declares which
modules may call which other modules. The mesh client consults this module
before dispatching every `Call()`.

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

```yaml
# Allow module to call any method on any target
- caller: "downloader-qbittorrent"
  target: "*"
  methods: ["*"]

# Allow specific call patterns
- caller: "media-movies"
  target: "transcoder-ffmpeg"
  methods: ["Transcode", "Status"]

# Development mode: allow all
- caller: "*"
  target: "*"
  methods: ["*"]
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy-file` | `policies.yaml` | Path to policy YAML file |
| `--allow-all` | `false` | Permit all inter-module calls (development) |
| `--deny-all` | `false` | Deny all inter-module calls (locked down) |

### Hot-Reload

SIGHUP reloads the policy file without restarting the module.

## Implementation

- Registers with capability: `"call.policy"`
- Implements `contracts.CallPolicyProvider`
- Also implements `contracts.ResourceCallPolicyProvider` for method-level control
- Audits denied calls via `AuditLogger`
- Exposes metrics: `call_policy_allowed_total`, `call_policy_denied_total`
