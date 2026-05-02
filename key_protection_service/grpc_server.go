package keyprotectionservice

import (
	"context"

	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcServer is the gRPC server wrapper for the KeyProtectionService.
type grpcServer struct {
	kpspb.UnimplementedKeyProtectionServiceServer
	svc *Service
}

// NewGrpcServer creates a new gRPC server wrapper for the KeyProtectionService.
func NewGrpcServer(svc *Service) *grpcServer {
	return &grpcServer{
		svc: svc,
	}
}

// GenerateKEMKeypair generates a new KEM keypair.
func (s *grpcServer) GenerateKEMKeypair(ctx context.Context, req *kpspb.GenerateKEMKeypairRequest) (*kpspb.GenerateKEMKeypairResponse, error) {
	id, pubKey, err := s.svc.GenerateKEMKeypair(ctx, req.Algo, req.BindingPubKey, req.LifespanSecs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate KEM keypair: %v", err)
	}

	return &kpspb.GenerateKEMKeypairResponse{
		KemUuid:   id.String(),
		KemPubKey: pubKey,
	}, nil
}

// DecapAndSeal decapsulates and reseals a shared secret.
func (s *grpcServer) DecapAndSeal(ctx context.Context, req *kpspb.DecapAndSealRequest) (*kpspb.DecapAndSealResponse, error) {
	kemUUID, err := uuid.Parse(req.KemUuid)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM UUID: %v", err)
	}

	sealEnc, sealedCt, err := s.svc.DecapAndSeal(ctx, kemUUID, req.EncapsulatedKey, req.Aad)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decap and seal: %v", err)
	}

	return &kpspb.DecapAndSealResponse{
		SealEnc:  sealEnc,
		SealedCt: sealedCt,
	}, nil
}

// EnumerateKEMKeys enumerates active KEM keys.
func (s *grpcServer) EnumerateKEMKeys(ctx context.Context, req *kpspb.EnumerateKEMKeysRequest) (*kpspb.EnumerateKEMKeysResponse, error) {
	keys, hasMore, err := s.svc.EnumerateKEMKeys(ctx, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to enumerate KEM keys: %v", err)
	}

	var pbKeys []*kpspb.KEMKeyInfo
	for _, k := range keys {
		pbKeys = append(pbKeys, &kpspb.KEMKeyInfo{
			Id:                    k.ID.String(),
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
	kemUUID, err := uuid.Parse(req.KemUuid)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM UUID: %v", err)
	}

	err = s.svc.DestroyKEMKey(ctx, kemUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to destroy KEM key: %v", err)
	}

	return &kpspb.DestroyKEMKeyResponse{}, nil
}

// GetKEMKey retrieves a KEM key's info.
func (s *grpcServer) GetKEMKey(ctx context.Context, req *kpspb.GetKEMKeyRequest) (*kpspb.GetKEMKeyResponse, error) {
	kemUUID, err := uuid.Parse(req.KemUuid)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid KEM UUID: %v", err)
	}

	kemPubKey, bindingPubKey, algo, lifespan, err := s.svc.GetKEMKey(ctx, kemUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get KEM key: %v", err)
	}

	return &kpspb.GetKEMKeyResponse{
		KemPubKey:             kemPubKey,
		BindingPubKey:         bindingPubKey,
		Algorithm:             algo,
		RemainingLifespanSecs: lifespan,
	}, nil
}
