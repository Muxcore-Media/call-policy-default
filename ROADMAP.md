# call-policy-default — Implementation Roadmap

**Priority:** P0 — Required before any module can communicate.

## Phases

### Phase 1: Static Allow-List (minimum viable)
- [x] Project scaffold (this repo)
- [ ] `go mod init` with core dependency
- [ ] YAML policy file parser
- [ ] `CallPolicyProvider` implementation (static allow-list by caller/target/method)
- [ ] Sidecar entry point (`cmd/module/main.go`)
- [ ] SIGHUP hot-reload for policy file
- [ ] Unit tests for policy matching (30+ test cases)
- [ ] Integration test with a running muxcored
- [ ] `--allow-all` flag
- [ ] GitHub CI (build + lint + test)

### Phase 2: Operational
- [ ] Audit logging of denied calls
- [ ] Prometheus metrics (allowed/denied counters)
- [ ] Health endpoint (gRPC health check)
- [ ] Module restart policy support
- [ ] Published events for policy changes

### Phase 3: Advanced
- [ ] Dynamic policy via event bus (modules request access at runtime)
- [ ] Rate-limited access patterns
- [ ] Time-based policies (allow during maintenance windows)
- [ ] Policy groups (apply same rules to multiple callers)

## Design Decisions

1. **YAML over JSON** — Easier for operators to write and review.
2. **Explicit allow, implicit deny** — Matches core's security philosophy.
3. **Hot-reload without restart** — Policy changes should not disrupt running calls.
4. **Wildcard support** — `"*"` matches everything, enabling development mode.
