//go:build !cgo || !linux || !amd64

package kpskcc

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestStubErrors(t *testing.T) {
	expected := "not supported on this architecture"

	_, _, err := GenerateKEMKeypair(nil, nil, 0)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("GenerateKEMKeypair() error = %v, want %q", err, expected)
	}

	_, _, err = EnumerateKEMKeys(0, 0)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("EnumerateKEMKeys() error = %v, want %q", err, expected)
	}

	_, _, _, _, err = GetKEMKey(uuid.Nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("GetKEMKey() error = %v, want %q", err, expected)
	}

	_, _, err = DecapAndSeal(uuid.Nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("DecapAndSeal() error = %v, want %q", err, expected)
	}

	err = DestroyKEMKey(uuid.Nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("DestroyKEMKey() error = %v, want %q", err, expected)
	}
}
