# call-policy-default — Remaining Work

### Operational
- [x] Audit logging of denied calls — core fire-and-forget at mesh enforcement (`call.policy.denied`); module keeps counters/`slog`
- [x] Health endpoint (gRPC health check)

### Advanced
- [ ] Dynamic policy via event bus (modules request access at runtime)
- [ ] Rate-limited access patterns
- [ ] Time-based policies (allow during maintenance windows)
- [ ] Policy groups (apply same rules to multiple callers)
