package workloadservice

import (
	"context"
	"fmt"
	"log"
	"net"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"google.golang.org/grpc"
)

// KeyClaimsGRPCServer implements the gRPC KeyClaimsService.
type KeyClaimsGRPCServer struct {
	keymanager.UnimplementedKeyClaimsServiceServer
	wsdServer *Server
}

// NewKeyClaimsGRPCServer creates a new KeyClaimsGRPCServer.
func NewKeyClaimsGRPCServer(wsdServer *Server) *KeyClaimsGRPCServer {
	return &KeyClaimsGRPCServer{wsdServer: wsdServer}
}

// GetKeyClaims handles requests for key claims.
func (s *KeyClaimsGRPCServer) GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error) {
	return s.wsdServer.handleGetClaims(req)
}

// StartKeyClaimsGRPCServer starts the gRPC server on the specified port.
// It runs the server in a goroutine and returns the grpc.Server instance.
func StartKeyClaimsGRPCServer(wsdServer *Server, port int) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	s := grpc.NewServer()
	keymanager.RegisterKeyClaimsServiceServer(s, NewKeyClaimsGRPCServer(wsdServer))
	log.Printf("gRPC server listening at %v", lis.Addr())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("gRPC server stopped: %v", err)
		}
	}()
	return s, nil
}
