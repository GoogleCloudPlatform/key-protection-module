package keymanager

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
)

func TestKeyHandleValidation(t *testing.T) {
	tests := []struct {
		name    string
		handle  string
		wantErr bool
	}{
		{name: "valid UUID", handle: uuid.NewString()},
		{name: "malformed UUID", handle: "not-a-uuid", wantErr: true},
		{name: "empty handle", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protovalidate.Validate(&KeyHandle{Handle: tc.handle})
			if (err != nil) != tc.wantErr {
				t.Fatalf("protovalidate.Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
