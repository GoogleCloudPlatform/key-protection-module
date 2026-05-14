// Package claimserver provides a unified KeyClaims gRPC server implementation
// shared across both Workload Service Daemon (WSD) and Key Protection Service (KPS).
package claimserver

import (
	"context"
	"fmt"
	"log"
	"net"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"google.golang.org/grpc"
)

// KeyClaimProvider abstracts the service-specific logic for fetching key claims.
type KeyClaimProvider interface {
	GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error)
}

type grpcServer struct {
	keymanager.UnimplementedKeyClaimsServiceServer
	provider KeyClaimProvider
}

func (s *grpcServer) GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error) {
	return s.provider.GetKeyClaims(ctx, req)
}

// Start starts a unified KeyClaims gRPC server on the specified port.
func Start(provider KeyClaimProvider, port int) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}
	s := grpc.NewServer()
	keymanager.RegisterKeyClaimsServiceServer(s, &grpcServer{provider: provider})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("KeyClaims gRPC server stopped: %v", err)
		}
	}()
	return s, lis, nil
}
