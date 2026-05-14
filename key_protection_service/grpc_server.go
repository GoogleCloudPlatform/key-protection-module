package keyprotectionservice

import (
	"context"
	"errors"

	"buf.build/go/protovalidate"
	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// grpcServer is the gRPC server wrapper for the KeyProtectionService.
type grpcServer struct {
	kpspb.UnimplementedKeyProtectionServiceServer
	svc       KeyProtectionService
	bootToken string
}

// NewGrpcServer creates a new gRPC server wrapper for the KeyProtectionService.
// It accepts the KeyProtectionService interface so tests can inject mocks
// directly without going through the production Service wrapper.
func NewGrpcServer(svc KeyProtectionService, bootToken string) kpspb.KeyProtectionServiceServer {
	return &grpcServer{
		svc:       svc,
		bootToken: bootToken,
	}
}

// ValidationInterceptor is a gRPC unary server interceptor that validates requests.
func ValidationInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	msg, ok := req.(proto.Message)
	if !ok {
		return nil, status.Errorf(codes.Internal, "request is not a proto message")
	}
	if err := protovalidate.Validate(msg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	return handler(ctx, req)
}

// grpcCodeFromError maps an FFI status error to a gRPC code so the WSD client
// can translate it back to the right HTTP status. Without this, the WSD HTTP
// API regresses to 500 for everything when running against a remote KPS.
var ffiErrorToGrpcCode = map[error]codes.Code{
	keymanager.Status_STATUS_NOT_FOUND:             codes.NotFound,
	keymanager.Status_STATUS_INVALID_ARGUMENT:      codes.InvalidArgument,
	keymanager.Status_STATUS_UNSUPPORTED_ALGORITHM: codes.InvalidArgument,
	keymanager.Status_STATUS_INVALID_KEY:           codes.InvalidArgument,
	keymanager.Status_STATUS_PERMISSION_DENIED:     codes.PermissionDenied,
	keymanager.Status_STATUS_UNAUTHENTICATED:       codes.Unauthenticated,
	keymanager.Status_STATUS_ALREADY_EXISTS:        codes.AlreadyExists,
}

func grpcCodeFromError(err error) codes.Code {
	for target, code := range ffiErrorToGrpcCode {
		if errors.Is(err, target) {
			return code
		}
	}
	return codes.Internal
}

// GenerateKEMKeypair generates a new KEM keypair.
func (s *grpcServer) GenerateKEMKeypair(ctx context.Context, req *kpspb.GenerateKEMKeypairRequest) (*kpspb.GenerateKEMKeypairResponse, error) {
	id, pubKey, err := s.svc.GenerateKEMKeypair(ctx, req.GetAlgo(), req.GetBindingPubKey().GetPublicKey(), req.GetLifespanSecs())
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to generate KEM keypair: %v", err)
	}

	return &kpspb.GenerateKEMKeypairResponse{
		KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
		KemPubKey: &keymanager.KemPublicKey{
			Algorithm: req.GetAlgo().GetKem(),
			PublicKey: pubKey,
		},
	}, nil
}

// DecapAndSeal decapsulates and reseals a shared secret.
func (s *grpcServer) DecapAndSeal(ctx context.Context, req *kpspb.DecapAndSealRequest) (*kpspb.DecapAndSealResponse, error) {
	kemUUID, err := uuid.Parse(req.GetKeyHandle().GetHandle())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM key handle: %v", err)
	}

	sealEnc, sealedCt, err := s.svc.DecapAndSeal(ctx, kemUUID, req.GetCiphertext().GetCiphertext(), req.GetAad())
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to decap and seal: %v", err)
	}

	return &kpspb.DecapAndSealResponse{
		SealEnc:  sealEnc,
		SealedCt: sealedCt,
	}, nil
}

// EnumerateKEMKeys enumerates active KEM keys.
func (s *grpcServer) EnumerateKEMKeys(ctx context.Context, req *kpspb.EnumerateKEMKeysRequest) (*kpspb.EnumerateKEMKeysResponse, error) {
	keys, hasMore, err := s.svc.EnumerateKEMKeys(ctx, int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to enumerate KEM keys: %v", err)
	}

	pbKeys := make([]*kpspb.KEMKeyInfo, 0, len(keys))
	for _, k := range keys {
		pbKeys = append(pbKeys, &kpspb.KEMKeyInfo{
			KeyHandle:             &keymanager.KeyHandle{Handle: k.ID.String()},
			Algorithm:             k.Algorithm,
			KemPubKey:             k.KEMPubKey,
			RemainingLifespanSecs: k.RemainingLifespanSecs,
		})
	}

	return &kpspb.EnumerateKEMKeysResponse{
		Keys:    pbKeys,
		HasMore: hasMore,
	}, nil
}

// DestroyKEMKey destroys a KEM key.
func (s *grpcServer) DestroyKEMKey(ctx context.Context, req *kpspb.DestroyKEMKeyRequest) (*kpspb.DestroyKEMKeyResponse, error) {
	kemUUID, err := uuid.Parse(req.GetKeyHandle().GetHandle())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM key handle: %v", err)
	}

	if err := s.svc.DestroyKEMKey(ctx, kemUUID); err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to destroy KEM key: %v", err)
	}

	return &kpspb.DestroyKEMKeyResponse{}, nil
}

// GetKEMKey retrieves a KEM key's info.
func (s *grpcServer) GetKEMKey(ctx context.Context, req *kpspb.GetKEMKeyRequest) (*kpspb.GetKEMKeyResponse, error) {
	kemUUID, err := uuid.Parse(req.GetKeyHandle().GetHandle())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM key handle: %v", err)
	}

	kemPubKey, bindingPubKey, algo, lifespan, err := s.svc.GetKEMKey(ctx, kemUUID)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to get KEM key: %v", err)
	}

	return &kpspb.GetKEMKeyResponse{
		KemPubKey: &keymanager.KemPublicKey{
			Algorithm: algo.GetKem(),
			PublicKey: kemPubKey,
		},
		BindingPubKey: &keymanager.HpkePublicKey{
			Algorithm: algo,
			PublicKey: bindingPubKey,
		},
		RemainingLifespanSecs: lifespan,
	}, nil
}

// Heartbeat implements the Heartbeat RPC.
func (s *grpcServer) Heartbeat(_ context.Context, _ *kpspb.HeartbeatRequest) (*kpspb.HeartbeatResponse, error) {
	return &kpspb.HeartbeatResponse{KpsBootToken: s.bootToken}, nil
}
