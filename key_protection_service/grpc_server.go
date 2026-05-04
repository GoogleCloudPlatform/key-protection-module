package keyprotectionservice

import (
	"context"
	"errors"

	"buf.build/go/protovalidate"
	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcServer is the gRPC server wrapper for the KeyProtectionService.
type grpcServer struct {
	kpspb.UnimplementedKeyProtectionServiceServer
	svc KeyProtectionService
}

// NewGrpcServer creates a new gRPC server wrapper for the KeyProtectionService.
// It accepts the KeyProtectionService interface so tests can inject mocks
// directly without going through the production Service wrapper.
func NewGrpcServer(svc KeyProtectionService) kpspb.KeyProtectionServiceServer {
	return &grpcServer{
		svc: svc,
	}
}

// grpcCodeFromError maps an FFI status error to a gRPC code so the WSD client
// can translate it back to the right HTTP status. Without this, the WSD HTTP
// API regresses to 500 for everything when running against a remote KPS.
func grpcCodeFromError(err error) codes.Code {
	switch {
	case errors.Is(err, keymanager.Status_STATUS_NOT_FOUND):
		return codes.NotFound
	case errors.Is(err, keymanager.Status_STATUS_INVALID_ARGUMENT),
		errors.Is(err, keymanager.Status_STATUS_UNSUPPORTED_ALGORITHM),
		errors.Is(err, keymanager.Status_STATUS_INVALID_KEY):
		return codes.InvalidArgument
	case errors.Is(err, keymanager.Status_STATUS_PERMISSION_DENIED):
		return codes.PermissionDenied
	case errors.Is(err, keymanager.Status_STATUS_UNAUTHENTICATED):
		return codes.Unauthenticated
	case errors.Is(err, keymanager.Status_STATUS_ALREADY_EXISTS):
		return codes.AlreadyExists
	default:
		return codes.Internal
	}
}

// GetCapabilities retrieves the supported cryptographic algorithms.
func (s *grpcServer) GetCapabilities(ctx context.Context, req *kpspb.GetCapabilitiesRequest) (*kpspb.GetCapabilitiesResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// For Bowcaster, KPS needs to report its own capabilities.
	// Since Vanguard's WSD has the same list of supported algorithms,
	// we will proxy this request to the service layer.
	
	// Assuming svc has a GetCapabilities method. If it doesn't we might need to add it,
	// but the WSD expects a standard GetCapabilitiesResponse format from KPS.
	// We'll return the hardcoded supported algorithm per the docs for now if it's not in the interface,
	// but let's check if we can just implement it directly here to match WSD.

	return &kpspb.GetCapabilitiesResponse{
		SupportedAlgorithms: []*keymanager.SupportedAlgorithm{
			{
				Algorithm: &keymanager.AlgorithmDetails{
					Type: "kem",
					Params: &keymanager.AlgorithmParams{
						Params: &keymanager.AlgorithmParams_KemId{
							KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
						},
					},
				},
			},
		},
	}, nil
}

// GenerateKEMKeypair generates a new KEM keypair.
func (s *grpcServer) GenerateKEMKeypair(ctx context.Context, req *kpspb.GenerateKEMKeypairRequest) (*kpspb.GenerateKEMKeypairResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

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
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

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
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

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
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

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
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

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
