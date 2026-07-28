//go:build !cgo || !linux || !amd64

package wskcc

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
)

// GenerateBindingKeypair is a stub for architectures where the Rust library is not supported.
func GenerateBindingKeypair(_ context.Context, _ *keymanager.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateBindingKeypair is not supported on this architecture")
}

// Open is a stub for architectures where the Rust library is not supported.
func Open(_ context.Context, _ uuid.UUID, _, _, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("Open is not supported on this architecture")
}

// DestroyBindingKey is a stub for architectures where the Rust library is not supported.
func DestroyBindingKey(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("DestroyBindingKey is not supported on this architecture")
}

// GetBindingKey is a stub for architectures where the Rust library is not supported.
func GetBindingKey(_ context.Context, id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return nil, nil, fmt.Errorf("GetBindingKey is not supported on this architecture")
}

// DestroyAllKeys is a stub for architectures where the Rust library is not supported.
func DestroyAllKeys(_ context.Context) error {
	return fmt.Errorf("DestroyAllKeys is not supported on this architecture")
}

// InitTelemetry is a no-op stub for architectures where the Rust library is not supported.
// InitTelemetry is a no-op stub for environments lacking CGO support.
func InitTelemetry(_ string) {}
