package server

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	policyv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/policy/v1"
)

// PolicyServer implements the PolicyService gRPC server for call policy enforcement.
type PolicyServer struct {
	policyv1.UnimplementedPolicyServiceServer
	policy *policy.Policy
}

// New creates a PolicyServer backed by the given policy.
func New(p *policy.Policy) *PolicyServer {
	return &PolicyServer{policy: p}
}

// RegisterWithGRPC registers the policy server with a gRPC server.
func (s *PolicyServer) RegisterWithGRPC(srv *grpc.Server) {
	policyv1.RegisterPolicyServiceServer(srv, s)
}

// AllowCall checks whether a caller module is permitted to call a method on a target module.
func (s *PolicyServer) AllowCall(ctx context.Context, req *policyv1.AllowCallRequest) (*policyv1.AllowCallResponse, error) {
	caller := req.GetCallerModuleId()
	target := req.GetTargetModuleId()
	method := req.GetMethod()

	if caller == "" || target == "" || method == "" {
		return nil, status.Error(codes.InvalidArgument, "caller_module_id, target_module_id, and method are required")
	}

	allowed, reason := s.policy.Allow(caller, target, method)
	if !allowed {
		slog.Warn("call policy: denied",
			"caller", caller,
			"target", target,
			"method", method,
			"reason", reason,
		)
		return &policyv1.AllowCallResponse{Allowed: false, Reason: reason}, nil
	}

	return &policyv1.AllowCallResponse{Allowed: true}, nil
}

// AllowPublish checks whether a caller module is permitted to publish events of a type.
func (s *PolicyServer) AllowPublish(ctx context.Context, req *policyv1.AllowPublishRequest) (*policyv1.AllowPublishResponse, error) {
	// For the call-policy module, publish policy is not implemented — delegate to
	// the publish-policy-default module. Return denied by default.
	caller := req.GetCallerModuleId()
	eventType := req.GetEventType()

	slog.Warn("publish policy: not implemented by call-policy-default, denying",
		"caller", caller,
		"event_type", eventType,
	)
	return &policyv1.AllowPublishResponse{
		Allowed: false,
		Reason:  "publish policy is not handled by this module — deploy publish-policy-default",
	}, nil
}
