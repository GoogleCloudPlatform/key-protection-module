package keyprotectionservice

import (
	"context"
	"fmt"
	"net"
	"time"

	kpsapi "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	claimserver "github.com/GoogleCloudPlatform/key-protection-module/km_common/claimserver"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	// KeyClaimPort is the TCP port used by the KeyClaims gRPC server in production.
	KeyClaimPort = 50051
)

// Server is the Key Protection Service gRPC server.
type Server struct {
	grpcServer       *grpc.Server
	listener         net.Listener
	keyClaimServer   *grpc.Server
	keyClaimListener net.Listener
	kps              KeyProtectionService
	bootToken        string
}

// GetKeyClaims implements claimserver.KeyClaimProvider for KEM keys.
func (s *Server) GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error) {
	if req.GetKeyType() != keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type for KPS key claims: %v", req.GetKeyType())
	}

	kemUUID, err := uuid.Parse(req.GetKeyHandle().GetHandle())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM key handle: %v", err)
	}

	kemPubKey, bindingPubKey, algo, lifespan, err := s.kps.GetKEMKey(ctx, kemUUID)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to get KEM key: %v", err)
	}

	remaining := time.Duration(lifespan) * time.Second

	return &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
				KemPubKey: &keymanager.KemPublicKey{
					Algorithm: algo.GetKem(),
					PublicKey: kemPubKey,
				},
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: algo,
					PublicKey: bindingPubKey,
				},
				RemainingLifespan: durationpb.New(remaining),
				ExpirationTime:    float64(time.Now().Unix()) + float64(lifespan),
			},
		},
	}, nil
}

// NewServer creates a new KPS gRPC server listening on the given TCP port, with an optional key claim port (default 50051).
func NewServer(port int, keyClaimPort ...int) (*Server, error) {
	kcPort := KeyClaimPort
	if len(keyClaimPort) > 0 {
		kcPort = keyClaimPort[0]
	}
	return newServerWithPort(port, kcPort, NewService())
}

// newServerWithKPS creates a new KPS gRPC server with dynamic key claim port for testing.
func newServerWithKPS(port int, keyClaimPort int, kps KeyProtectionService) (*Server, error) {
	return newServerWithPort(port, keyClaimPort, kps)
}

func newServerWithPort(port int, keyClaimPort int, kps KeyProtectionService) (*Server, error) {
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

	s := &Server{
		grpcServer: grpcServer,
		listener:   ln,
		kps:        kps,
		bootToken:  bootToken,
	}

	keyClaimServer, keyClaimLis, err := claimserver.Start(s, keyClaimPort)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to start KeyClaims gRPC server: %w", err)
	}

	s.keyClaimServer = keyClaimServer
	s.keyClaimListener = keyClaimLis

	return s, nil
}

// Serve starts the gRPC server listening on the given port.
func (s *Server) Serve() error {
	return s.grpcServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.keyClaimServer != nil {
		s.keyClaimServer.GracefulStop()
	}

	shutdownDone := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(shutdownDone)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.Stop() // Force stop if context is cancelled
		return ctx.Err()
	case <-shutdownDone:
		return nil
	}
}
