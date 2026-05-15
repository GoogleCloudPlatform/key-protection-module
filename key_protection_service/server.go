package keyprotectionservice

import (
	"context"
	"fmt"
	"net"

	kpsapi "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// Server is the Key Protection Service gRPC server.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	kps        KeyProtectionService
	bootToken  string
}

// NewServer creates a new KPS gRPC server listening on the given TCP port.
func NewServer(port int) (*Server, error) {
	return newServerWithKPS(port, NewService())
}

// newServerWithKPS creates a new KPS gRPC server with the given dependencies.
func newServerWithKPS(port int, kps KeyProtectionService) (*Server, error) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP port %d: %w", port, err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(ValidationInterceptor),
	)

	bootToken := uuid.New().String()
	kpsapi.RegisterKeyProtectionServiceServer(grpcServer, NewGrpcServer(kps, bootToken))

	return &Server{
		grpcServer: grpcServer,
		listener:   ln,
		kps:        kps,
		bootToken:  bootToken,
	}, nil

}

// Serve starts the gRPC server listening on the given port.
func (s *Server) Serve() error {
	if err := s.grpcServer.Serve(s.listener); err != nil {
		return fmt.Errorf("failed to serve KPS gRPC server: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownDone := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(shutdownDone)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.Stop() // Force stop if context is cancelled
		return fmt.Errorf("KPS gRPC shutdown context cancelled: %w", ctx.Err())
	case <-shutdownDone:
		return nil
	}
}
