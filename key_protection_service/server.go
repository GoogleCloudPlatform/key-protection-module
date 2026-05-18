package keyprotectionservice

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	kpsapi "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	// math.MaxInt64 nanoseconds is approx 292 years or 9223372036 seconds.
	maxDurationSeconds = math.MaxInt64 / int64(time.Second)
)

// Server is the Key Protection Service gRPC server.
type Server struct {
	keymanager.UnimplementedKeyClaimsServiceServer
	grpcServer *grpc.Server
	listener   net.Listener
	kps        KeyProtectionService
	bootToken  string
	mode       keymanager.KeyProtectionMechanism
	role       keymanager.ServiceRole
}

// GetKeyClaims implements keymanager.KeyClaimsServiceServer for KEM keys.
func (s *Server) GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error) {
	if s.mode != keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM || s.role != keymanager.ServiceRole_SERVICE_ROLE_KPS {
		return nil, status.Errorf(codes.PermissionDenied, "KEM key claims can only be retrieved from KPS VM in KEY_PROTECTION_VM mode and SERVICE_ROLE_KPS role")
	}

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

	var remaining time.Duration
	if lifespan > uint64(maxDurationSeconds) {
		remaining = time.Duration(math.MaxInt64)
	} else {
		remaining = time.Duration(lifespan) * time.Second
	}

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

// NewServer creates a new KPS gRPC server listening on the given TCP port.
func NewServer(port int, mode keymanager.KeyProtectionMechanism, role keymanager.ServiceRole) (*Server, error) {
	return newServerWithKPS(port, NewService(), mode, role)
}

// newServerWithKPS creates a new KPS gRPC server with the given dependencies.
func newServerWithKPS(port int, kps KeyProtectionService, mode keymanager.KeyProtectionMechanism, role keymanager.ServiceRole) (*Server, error) {
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
		mode:       mode,
		role:       role,
	}

	keymanager.RegisterKeyClaimsServiceServer(grpcServer, s)

	return s, nil
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
