# call-policy-default — Remaining Work

### Operational
- [x] Audit logging of denied calls — core fire-and-forget at mesh enforcement (`call.policy.denied`); module keeps counters/`slog`
- [x] Health endpoint (gRPC health check)

### Advanced
- [x] Dynamic policy via event bus (modules request access at runtime) — `call.policy.grant` / `call.policy.revoke` (v0.3.0)
- [x] Rate-limited access patterns
- [x] Time-based policies (allow during maintenance windows)
- [x] Policy groups (apply same rules to multiple callers)
