// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build cgo && linux && amd64

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	kpskcc "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/key_custody_core"
	wskcc "github.com/GoogleCloudPlatform/key-protection-module/workload_service/key_custody_core"
	"github.com/google/uuid"
)

const telemetryChildModeEnv = "KPM_TELEMETRY_CHILD_MODE"

func TestRustTelemetryServiceNameAcrossLinkedKCCs(t *testing.T) {
	if mode := os.Getenv(telemetryChildModeEnv); mode != "" {
		switch mode {
		case "wsd":
			// Emulated WSD initializes telemetry through the WSD wrapper, then uses
			// both KCCs. A KPS failure must retain the WSD process service name.
			wskcc.InitTelemetry("workload_service")
		case "kps":
			kpskcc.InitTelemetry("key_protection_service")
		default:
			t.Fatalf("unknown child mode %q", mode)
		}

		if err := kpskcc.DestroyKEMKey(uuid.Nil); err == nil {
			t.Fatal("DestroyKEMKey() unexpectedly succeeded")
		}
		return
	}

	tests := []struct {
		name              string
		mode              string
		wantService       string
		unexpectedService string
	}{
		{
			name:              "WSD initialization applies to KPS KCC",
			mode:              "wsd",
			wantService:       "workload_service",
			unexpectedService: "key_protection_service",
		},
		{
			name:              "KPS initialization applies to KPS KCC",
			mode:              "kps",
			wantService:       "key_protection_service",
			unexpectedService: "workload_service",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRustTelemetryServiceNameAcrossLinkedKCCs$")
			cmd.Env = append(os.Environ(), telemetryChildModeEnv+"="+tc.mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child test failed: %v\n%s", err, output)
			}

			text := string(output)
			if !strings.Contains(text, `"service.name":"`+tc.wantService+`"`) {
				t.Fatalf("missing service.name %q in output:\n%s", tc.wantService, text)
			}
			if strings.Contains(text, `"service.name":"`+tc.unexpectedService+`"`) {
				t.Fatalf("unexpected service.name %q in output:\n%s", tc.unexpectedService, text)
			}
			if count := strings.Count(text, `"kcc_operation_failed"`); count != 1 {
				t.Fatalf("got %d failure events, want 1:\n%s", count, text)
			}
			if !strings.Contains(text, `"operation":"destroy_kem_key"`) {
				t.Fatalf("missing destroy_kem_key operation in output:\n%s", text)
			}
		})
	}
}
