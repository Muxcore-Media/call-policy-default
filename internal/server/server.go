package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	policyv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/policy/v1"
)

// PolicyServer implements the PolicyService gRPC server for call policy enforcement.
type PolicyServer struct {
	policyv1.UnimplementedPolicyServiceServer
	policy      *policy.Policy
	allowed     atomic.Int64
	denied      atomic.Int64
}

// New creates a PolicyServer backed by the given policy.
func New(p *policy.Policy) *PolicyServer {
	return &PolicyServer{policy: p}
}

// RegisterWithGRPC registers the policy server with a gRPC server.
func (s *PolicyServer) RegisterWithGRPC(srv *grpc.Server) {
	policyv1.RegisterPolicyServiceServer(srv, s)
}

// Metrics returns Prometheus-format metrics text.
func (s *PolicyServer) Metrics() string {
	var b strings.Builder
	b.WriteString("# HELP call_policy_allowed_total Total inter-module calls allowed by policy\n")
	b.WriteString("# TYPE call_policy_allowed_total counter\n")
	fmt.Fprintf(&b, "call_policy_allowed_total %d\n", s.allowed.Load())
	b.WriteString("# HELP call_policy_denied_total Total inter-module calls denied by policy\n")
	b.WriteString("# TYPE call_policy_denied_total counter\n")
	fmt.Fprintf(&b, "call_policy_denied_total %d\n", s.denied.Load())
	return b.String()
}

func (s *PolicyServer) AllowCall(ctx context.Context, req *policyv1.AllowCallRequest) (*policyv1.AllowCallResponse, error) {
	caller := req.GetCallerModuleId()
	target := req.GetTargetModuleId()
	method := req.GetMethod()

	if caller == "" || target == "" || method == "" {
		return nil, status.Error(codes.InvalidArgument, "caller_module_id, target_module_id, and method are required")
	}

	allowed, reason := s.policy.Allow(caller, target, method)
	if !allowed {
		s.denied.Add(1)
		slog.Warn("call policy: denied",
			"caller", caller,
			"target", target,
			"method", method,
			"reason", reason,
		)
		return &policyv1.AllowCallResponse{Allowed: false, Reason: reason}, nil
	}

	s.allowed.Add(1)
	return &policyv1.AllowCallResponse{Allowed: true}, nil
}

func (s *PolicyServer) AllowPublish(ctx context.Context, req *policyv1.AllowPublishRequest) (*policyv1.AllowPublishResponse, error) {
	slog.Warn("publish policy: not implemented by call-policy-default, denying",
		"caller", req.GetCallerModuleId(),
		"event_type", req.GetEventType(),
	)
	return &policyv1.AllowPublishResponse{
		Allowed: false,
		Reason:  "publish policy is not handled by this module — deploy publish-policy-default",
	}, nil
}

// SetPolicy replaces the policy at runtime (for testing).
func (s *PolicyServer) SetPolicy(p *policy.Policy) {
	s.policy = p
}
