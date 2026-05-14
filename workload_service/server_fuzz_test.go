// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workloadservice

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	api "github.com/GoogleCloudPlatform/key-protection-module/workload_service/proto"
)

func FuzzHandleGenerateKey(f *testing.F) {
	// Seed corpus: valid request
	f.Add([]byte(`{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":3600}`))
	// Invalid requests to help fuzzer explore error paths
	f.Add([]byte(`{"algorithm":{"type":"mac","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":3600}`))
	f.Add([]byte(`{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_UNSPECIFIED"}},"lifespan":3600}`))
	f.Add([]byte(`{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":0}`))
	f.Add([]byte(`not even json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		socketPath := filepath.Join(t.TempDir(), "fuzz.sock")
		srv, err := NewServer(&keyProtectionService{}, &workloadService{}, socketPath)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		defer func() { _ = srv.Shutdown(context.Background()) }()

		req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
	})
}

func FuzzHandleDecaps(f *testing.F) {
	// Seed corpus: valid format but with dummy data
	f.Add([]byte(`{"ciphertext": {"algorithm": 1, "ciphertext": "Y2lwaGVydGV4dA=="}, "key_handle": {"handle": "00000000-0000-0000-0000-000000000000"}}`))
	f.Add([]byte(`{"ciphertext": {"algorithm": 0, "ciphertext": "Y2lwaGVydGV4dA=="}, "key_handle": {"handle": "00000000-0000-0000-0000-000000000000"}}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		socketPath := filepath.Join(t.TempDir(), "fuzz_decap.sock")
		srv, err := NewServer(&keyProtectionService{}, &workloadService{}, socketPath)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		defer func() { _ = srv.Shutdown(context.Background()) }()

		// Pre-generate a key to make the environment stateful.
		// This populates the global Rust registry and the Go mapping.
		genReqBody := []byte(`{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":3600}`)
		reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(genReqBody))
		reqGen.Header.Set("Content-Type", "application/json")
		wGen := httptest.NewRecorder()
		srv.Handler().ServeHTTP(wGen, reqGen)

		var validHandle string
		if wGen.Code == http.StatusOK {
			var resp api.GenerateKeyResponse
			if err := protojson.Unmarshal(wGen.Body.Bytes(), &resp); err == nil {
				validHandle = resp.KeyHandle.Handle
			}
		}

		// Structure-aware fuzzing: If fuzzed bytes form a valid DecapsRequest structure,
		// we inject the active validHandle generated above to bypass the early-exit 404 check
		// and fuzz the deeper HPKE decapsulation/decryption logic in the Rust FFI layer.
		if err := protojson.Unmarshal(data, &api.DecapsRequest{}); err == nil {
			if validHandle != "" {
				var decapsReq api.DecapsRequest
				if err := protojson.Unmarshal(data, &decapsReq); err == nil {
					// Inject valid handle
					if decapsReq.KeyHandle == nil {
						decapsReq.KeyHandle = &keymanager.KeyHandle{}
					}
					decapsReq.KeyHandle.Handle = validHandle

					// Marshal back to JSON
					if modifiedData, err := protojson.Marshal(&decapsReq); err == nil {
						data = modifiedData
					}
				}
			}
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
	})
}
