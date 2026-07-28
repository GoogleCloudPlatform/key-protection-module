//go:build !cgo || !linux || !amd64

package kpskcc

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
)

// GenerateKEMKeypair is a stub for architectures where the Rust library is not supported.
func GenerateKEMKeypair(_ context.Context, _ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateKEMKeypair is not supported on this architecture")
}

// EnumerateKEMKeys is a stub for architectures where the Rust library is not supported.
func EnumerateKEMKeys(_ context.Context, limit, offset int32) ([]KEMKeyInfo, bool, error) {
	return nil, false, fmt.Errorf("EnumerateKEMKeys is not supported on this architecture")
}

// GetKEMKey is a stub for architectures where the Rust library is not supported.
func GetKEMKey(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return nil, nil, nil, 0, fmt.Errorf("GetKEMKey is not supported on this architecture")
}

// DecapAndSeal is a stub for architectures where the Rust library is not supported.
func DecapAndSeal(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("DecapAndSeal is not supported on this architecture")
}

// DestroyKEMKey is a stub for architectures where the Rust library is not supported.
func DestroyKEMKey(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("DestroyKEMKey is not supported on this architecture")
}

// InitTelemetry is a no-op stub for architectures where the Rust library is not supported.
// InitTelemetry is a no-op stub for environments lacking CGO support.
func InitTelemetry(_ string) {}
