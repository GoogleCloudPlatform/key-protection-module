package service

import (
	"context"
	"fmt"
	"net"

	"github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/go-tpm-tools/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"
)

// Server is used to implement pb.AttestationServiceServer.
type Server struct {
	server *grpc.Server
	net.Listener
}

type handler struct {
	pb.UnimplementedAttestationServiceServer
	agent.AttestationAgent
}

func New(ctx context.Context, nl net.Listener, a agent.AttestationAgent) *Server {
	server := grpc.NewServer()
	pb.RegisterAttestationServiceServer(server, &handler{
		AttestationAgent: a,
	})

	return &Server{
		server:   server,
		Listener: nl,
	}
}

// GetKeyEndorsement implements pb.AttestationServiceServer
func (h *handler) GetKeyEndorsement(ctx context.Context, req *pb.GetKeyEndorsementRequest) (*pb.GetKeyEndorsementResponse, error) {
	if len(req.Challenge) == 0 {
		return nil, status.Error(codes.InvalidArgument, "challenge is required")
	}
	if req.KeyHandle == nil || len(req.KeyHandle.Handle) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key_handle is required")
	}

	// TODO(yawangwang): Call containerized KPS service to get KEM key claims.
	kemKeyClaims, err := stubKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get KEM key claims: %v", err))
	}

	kemBytes, err := proto.Marshal(kemKeyClaims)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to marshal KEM key claims: %v", err))
	}

	kemEvidence, err := h.AttestationAgent.AttestationEvidence(ctx, req.Challenge, kemBytes, agent.AttestAgentOpts{})
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to collect attestation evidence with KEM key claims: %v", err))
	}

	return &pb.GetKeyEndorsementResponse{
		KeyAttestation: &attestationpb.KeyAttestation{
			Attestation: kemEvidence,
		},
	}, nil
}

func (s *Server) Serve() error {
	return s.server.Serve(s.Listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Create a channel to track graceful stop completion.
	stopped := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		s.server.Stop()
		return ctx.Err()
	case <-stopped:
		return nil
	}
}

func stubKeyClaims(_ context.Context, _ string, keyType keymanager.KeyType) (*keymanager.KeyClaims, error) {
	if keyType != keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY {
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}
	return &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{},
		},
	}, nil
}
