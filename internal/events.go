package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	eventsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/events/v1"
	"github.com/Muxcore-Media/core/sdk/go/client"
)

const (
	eventCallPolicyGrant  = "call.policy.grant"
	eventCallPolicyRevoke = "call.policy.revoke"
)

type grantPayload struct {
	ID         string   `json:"id"`
	Caller     string   `json:"caller"`
	Target     string   `json:"target"`
	Methods    []string `json:"methods"`
	TTLSeconds int      `json:"ttl_seconds"`
}

type revokePayload struct {
	ID     string `json:"id"`
	Caller string `json:"caller"`
	Target string `json:"target"`
}

func (m *Module) dialCore(ctx context.Context) bool {
	if m.mc != nil {
		return true
	}
	meshAddr := os.Getenv("MUXCORE_GRPC_ADDR")
	if meshAddr == "" {
		meshAddr = "localhost:9090"
	}
	insecureMode := os.Getenv("MUXCORE_INSECURE_DISABLE_TLS") == "true" || os.Getenv("MUXCORE_GRPC_INSECURE") == "true"
	var opts []client.Option
	if insecureMode {
		opts = append(opts, client.WithInsecure())
	}
	c, err := client.Dial(meshAddr, opts...)
	if err != nil {
		slog.Warn("call-policy: dial core for dynamic grants", "error", err)
		return false
	}
	m.meshMu.Lock()
	if m.mc != nil {
		_ = c.Close()
		m.meshMu.Unlock()
		return true
	}
	m.mc = c
	m.meshMu.Unlock()
	slog.Info("call-policy: connected to core mesh for policy events", "addr", meshAddr)
	return true
}

func (m *Module) subscribePolicyEvents(ctx context.Context) {
	initialDelay := 5 * time.Second
	if v := os.Getenv("CALL_POLICY_EVENT_SUBSCRIBE_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			initialDelay = d
		}
	}
	retryDelay := 5 * time.Second
	first := true

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		delay := retryDelay
		if first {
			delay = initialDelay
			first = false
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		if !m.dialCore(ctx) {
			continue
		}

		var wg sync.WaitGroup
		subscribed := 0
		for _, et := range []string{eventCallPolicyGrant, eventCallPolicyRevoke} {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ch, cancel, err := m.mc.Events.Subscribe(ctx, et)
			if err != nil {
				slog.Warn("call-policy: subscribe failed", "type", et, "error", err)
				cancel()
				continue
			}
			subscribed++
			wg.Add(1)
			go func(eventType string, ch <-chan *eventsv1.Event, cancel context.CancelFunc) {
				defer wg.Done()
				m.handlePolicyEventStream(ctx, eventType, ch, cancel)
			}(et, ch, cancel)
			slog.Info("call-policy: subscribed to dynamic policy events", "type", et)
		}

		if subscribed == 0 {
			continue
		}

		wg.Wait()
		if ctx.Err() != nil {
			return
		}
		slog.Warn("call-policy: policy event stream ended; retrying subscribe")
	}
}

func (m *Module) handlePolicyEventStream(ctx context.Context, eventType string, ch <-chan *eventsv1.Event, cancel context.CancelFunc) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			switch eventType {
			case eventCallPolicyGrant:
				m.applyGrant(evt.GetSource(), evt.Payload)
			case eventCallPolicyRevoke:
				m.applyRevoke(evt.GetSource(), evt.Payload)
			}
		}
	}
}

func (m *Module) grantorAllowed(source string) bool {
	if m.policy == nil {
		return false
	}
	return m.policy.GrantorAllowed(source)
}

func (m *Module) applyGrant(source string, payload []byte) {
	if !m.grantorAllowed(source) {
		slog.Warn("call-policy: grant rejected — source not on grantor allowlist", "source", source)
		return
	}
	var g grantPayload
	if err := json.Unmarshal(payload, &g); err != nil {
		slog.Warn("call-policy: invalid grant payload", "error", err)
		return
	}
	ttl := time.Duration(g.TTLSeconds) * time.Second
	id, err := m.policy.GrantDynamic(g.ID, g.Caller, g.Target, g.Methods, ttl)
	if err != nil {
		slog.Warn("call-policy: grant rejected", "error", err, "caller", g.Caller, "target", g.Target)
		return
	}
	slog.Info("call-policy: dynamic grant applied",
		"id", id, "source", source, "caller", g.Caller, "target", g.Target, "methods", g.Methods, "ttl_seconds", g.TTLSeconds)
}

func (m *Module) applyRevoke(source string, payload []byte) {
	if !m.grantorAllowed(source) {
		slog.Warn("call-policy: revoke rejected — source not on grantor allowlist", "source", source)
		return
	}
	var r revokePayload
	if err := json.Unmarshal(payload, &r); err != nil {
		slog.Warn("call-policy: invalid revoke payload", "error", err)
		return
	}
	if r.ID != "" {
		if m.policy.RevokeDynamic(r.ID) {
			slog.Info("call-policy: dynamic grant revoked", "id", r.ID, "source", source)
			return
		}
		slog.Debug("call-policy: revoke id not found", "id", r.ID)
		return
	}
	n := m.policy.RevokeDynamicMatch(r.Caller, r.Target)
	if n == 0 {
		slog.Debug("call-policy: revoke matched nothing", "caller", r.Caller, "target", r.Target)
		return
	}
	slog.Info("call-policy: dynamic grants revoked by match",
		"count", n, "source", source, "caller", r.Caller, "target", r.Target)
}

// HandleGrantForTest applies a grant payload without the event bus (unit tests).
func (m *Module) HandleGrantForTest(source string, payload []byte) error {
	if m.policy == nil {
		return fmt.Errorf("not initialized")
	}
	m.applyGrant(source, payload)
	return nil
}

// HandleRevokeForTest applies a revoke payload without the event bus (unit tests).
func (m *Module) HandleRevokeForTest(source string, payload []byte) error {
	if m.policy == nil {
		return fmt.Errorf("not initialized")
	}
	m.applyRevoke(source, payload)
	return nil
}
