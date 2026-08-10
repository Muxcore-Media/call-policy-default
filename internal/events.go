package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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

func (m *Module) dialCore() {
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
		return
	}
	m.mc = c
	slog.Info("call-policy: connected to core mesh for policy events", "addr", meshAddr)
}

func (m *Module) subscribePolicyEvents() {
	delay := 5 * time.Second
	if v := os.Getenv("CALL_POLICY_EVENT_SUBSCRIBE_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			delay = d
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if m.mc == nil {
		m.dialCore()
	}
	if m.mc == nil {
		slog.Warn("call-policy: no mesh client; dynamic grant events disabled")
		return
	}

	for _, et := range []string{eventCallPolicyGrant, eventCallPolicyRevoke} {
		ch, cancel, err := m.mc.Events.Subscribe(context.Background(), et)
		if err != nil {
			slog.Warn("call-policy: subscribe failed", "type", et, "error", err)
			continue
		}
		go m.handlePolicyEventStream(et, ch, cancel)
		slog.Info("call-policy: subscribed to dynamic policy events", "type", et)
	}
}

func (m *Module) handlePolicyEventStream(eventType string, ch <-chan *eventsv1.Event, cancel context.CancelFunc) {
	defer cancel()
	for evt := range ch {
		switch eventType {
		case eventCallPolicyGrant:
			m.applyGrant(evt.Payload)
		case eventCallPolicyRevoke:
			m.applyRevoke(evt.Payload)
		}
	}
}

func (m *Module) applyGrant(payload []byte) {
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
		"id", id, "caller", g.Caller, "target", g.Target, "methods", g.Methods, "ttl_seconds", g.TTLSeconds)
}

func (m *Module) applyRevoke(payload []byte) {
	var r revokePayload
	if err := json.Unmarshal(payload, &r); err != nil {
		slog.Warn("call-policy: invalid revoke payload", "error", err)
		return
	}
	if r.ID != "" {
		if m.policy.RevokeDynamic(r.ID) {
			slog.Info("call-policy: dynamic grant revoked", "id", r.ID)
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
		"count", n, "caller", r.Caller, "target", r.Target)
}

// HandleGrantForTest applies a grant payload without the event bus (unit tests).
func (m *Module) HandleGrantForTest(payload []byte) error {
	if m.policy == nil {
		return fmt.Errorf("not initialized")
	}
	m.applyGrant(payload)
	return nil
}
