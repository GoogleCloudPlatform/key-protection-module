package kpskcc

import (
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
)

// KEMKeyInfo holds metadata for a single KEM key returned by EnumerateKEMKeys.
type KEMKeyInfo struct {
	ID                    uuid.UUID
	Algorithm             *keymanager.HpkeAlgorithm
	KEMPubKey             []byte
	RemainingLifespanSecs uint64
}
