# call-policy-default — Implementation Roadmap

**Priority:** P0 — Required before any module can communicate.

## Phases

### Phase 1: Static Allow-List (minimum viable) ✅
- [x] Project scaffold (this repo)
- [x] `go mod init` with core dependency
- [x] YAML policy file parser (`internal/policy`)
- [x] `CallPolicyProvider` implementation (static allow-list by caller/target/method)
- [x] gRPC `PolicyService` server for core queries (`internal/server`)
- [x] Core proto additions: `proto/muxcore/policy/v1/policy.proto` + adapter
- [x] Sidecar entry point (`cmd/module/main.go`)
- [x] SIGHUP hot-reload for policy file
- [x] Unit tests for policy matching (25+ test cases)
- [x] Unit tests for gRPC server (5 test cases)
- [x] `--allow-all` flag
- [x] Sample `policies.yaml`

### Phase 2: Operational
- [ ] Audit logging of denied calls
- [ ] Prometheus metrics (allowed/denied counters)
- [ ] Health endpoint (gRPC health check)
- [ ] Integration test with running muxcored
- [ ] GitHub CI (build + lint + test)

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
