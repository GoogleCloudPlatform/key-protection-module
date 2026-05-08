//go:build !cgo || !linux || !amd64

package wskcc

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestStubErrors(t *testing.T) {
	expected := "not supported on this architecture"

	_, _, err := GenerateBindingKeypair(nil, 0)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("GenerateBindingKeypair() error = %v, want %q", err, expected)
	}

	_, err = Open(uuid.Nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("Open() error = %v, want %q", err, expected)
	}

	err = DestroyBindingKey(uuid.Nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("DestroyBindingKey() error = %v, want %q", err, expected)
	}

	_, _, err = GetBindingKey(uuid.Nil)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Errorf("GetBindingKey() error = %v, want %q", err, expected)
	}
}
