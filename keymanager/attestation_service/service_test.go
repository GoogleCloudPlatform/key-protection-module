package service

import (
	"context"
	"fmt"
	"net"
	"testing"

	"strings"
	"time"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"
	"github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/go-tpm-tools/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type mockAgent struct {
	agent.AttestationAgent
	attestationEvidenceFn func(ctx context.Context, challenge []byte, extraData []byte, opts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error)
}

func (m *mockAgent) AttestationEvidence(ctx context.Context, challenge []byte, extraData []byte, opts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	if m.attestationEvidenceFn != nil {
		return m.attestationEvidenceFn(ctx, challenge, extraData, opts)
	}
	return nil, fmt.Errorf("unimplemented")
}

func (m *mockAgent) Close() error {
	return nil
}

type mockKeyClaimsClient struct {
	keymanager.KeyClaimsServiceClient
	getKeyClaimsFn func(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error)
}

func (m *mockKeyClaimsClient) GetKeyClaims(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error) {
	if m.getKeyClaimsFn != nil {
		return m.getKeyClaimsFn(ctx, in, opts...)
	}
	return nil, fmt.Errorf("unimplemented")
}

func TestGetKeyEndorsement_GRPC(t *testing.T) {
	expectedEvidence := &attestationpb.VmAttestation{Label: []byte("test-label")}

	defaultKPSFn := func(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error) {
		return &keymanager.KeyClaims{
			Claims: &keymanager.KeyClaims_VmKeyClaims{
				VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
					KemPubKey: &keymanager.KemPublicKey{
						Algorithm: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
						PublicKey: []byte("mock-kem-pub-key"),
					},
					BindingPubKey: &keymanager.HpkePublicKey{
						Algorithm: &keymanager.HpkeAlgorithm{
							Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
							Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
							Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
						},
						PublicKey: []byte("mock-binding-pub-key"),
					},
					ExpirationTime: float64(time.Now().Unix()) + 3600,
				},
			},
		}, nil
	}

	tests := []struct {
		name            string
		req             *pb.GetKeyEndorsementRequest
		agentFn         func(_ context.Context, challenge []byte, _ []byte, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error)
		kpsFn           func(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error)
		wantCode        codes.Code
		wantEvidence    *attestationpb.VmAttestation
		ctxFn           func(parent context.Context) (context.Context, context.CancelFunc)
		wantErrMsg      string
		timeoutOverride time.Duration
	}{
		{
			name: "Success_WithAcpiData",
			req: &pb.GetKeyEndorsementRequest{
				Challenge:       []byte("test-challenge"),
				KeyHandle:       &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
				RequestAcpiData: true,
			},
			agentFn: func(_ context.Context, challenge []byte, _ []byte, opts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
				if string(challenge) != "test-challenge" {
					t.Errorf("expected challenge 'test-challenge', got %q", string(challenge))
				}
				if opts.AcpiOpts == nil || !opts.AcpiOpts.RetrieveAcpiData {
					t.Errorf("expected RetrieveAcpiData to be true, got %v", opts.AcpiOpts)
				}
				return expectedEvidence, nil
			},
			kpsFn:        defaultKPSFn,
			wantCode:     codes.OK,
			wantEvidence: expectedEvidence,
		},
		{
			name: "Success_WithoutAcpiData",
			req: &pb.GetKeyEndorsementRequest{
				Challenge:       []byte("test-challenge"),
				KeyHandle:       &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
				RequestAcpiData: false,
			},
			agentFn: func(_ context.Context, challenge []byte, _ []byte, opts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
				if string(challenge) != "test-challenge" {
					t.Errorf("expected challenge 'test-challenge', got %q", string(challenge))
				}
				if opts.AcpiOpts != nil && opts.AcpiOpts.RetrieveAcpiData {
					t.Errorf("expected RetrieveAcpiData to be false, got true")
				}
				return expectedEvidence, nil
			},
			kpsFn:        defaultKPSFn,
			wantCode:     codes.OK,
			wantEvidence: expectedEvidence,
		},
		{
			name: "MissingChallenge",
			req: &pb.GetKeyEndorsementRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "NilKeyHandle",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "EmptyKeyHandle",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
				KeyHandle: &keymanager.KeyHandle{},
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "AgentError",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
				KeyHandle: &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
			},
			agentFn: func(_ context.Context, challenge []byte, _ []byte, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
				return nil, fmt.Errorf("agent error")
			},
			kpsFn:    defaultKPSFn,
			wantCode: codes.Internal,
		},
		{
			name: "KPSError",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
				KeyHandle: &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
			},
			kpsFn: func(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error) {
				return nil, fmt.Errorf("kps error")
			},
			wantCode: codes.Internal,
		},
		{
			name: "KPSTimeout",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
				KeyHandle: &keymanager.KeyHandle{Handle: "123e4567-e89b-12d3-a456-426614174000"},
			},
			timeoutOverride: 50 * time.Millisecond,
			kpsFn: func(ctx context.Context, in *keymanager.GetKeyClaimsRequest, opts ...grpc.CallOption) (*keymanager.KeyClaims, error) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(150 * time.Millisecond):
					return &keymanager.KeyClaims{}, nil
				}
			},
			wantCode:   codes.Internal,
			wantErrMsg: "context deadline exceeded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.timeoutOverride != 0 {
				oldTimeout := defaultKPSTimeout
				defaultKPSTimeout = tc.timeoutOverride
				defer func() { defaultKPSTimeout = oldTimeout }()
			}

			mockAgent := &mockAgent{
				attestationEvidenceFn: tc.agentFn,
			}
			mockKps := &mockKeyClaimsClient{
				getKeyClaimsFn: tc.kpsFn,
			}

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}

			server := New(t.Context(), lis, mockAgent, mockKps)
			go func() {
				if err := server.Serve(); err != nil {
					// This might fail when server is stopped, which is fine in tests
					t.Logf("server.Serve returned: %v", err)
				}
			}()
			defer server.Shutdown(t.Context())

			// Connect client
			conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer conn.Close()

			client := pb.NewAttestationServiceClient(conn)

			ctx := t.Context()
			if tc.ctxFn != nil {
				var cancel context.CancelFunc
				ctx, cancel = tc.ctxFn(ctx)
				defer cancel()
			}

			resp, err := client.GetKeyEndorsement(ctx, tc.req)

			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected status code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}

			if tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrMsg, err.Error())
				}
			}

			if tc.wantCode == codes.OK {
				if resp == nil {
					t.Fatal("expected non-nil response, got nil")
				}
				// Compare labels as a simple check, since we can't easily compare full proto messages directly without proto.Equal
				if string(resp.KeyAttestation.Attestation.Label) != string(tc.wantEvidence.Label) {
					t.Errorf("expected evidence label %q, got %q", string(tc.wantEvidence.Label), string(resp.KeyAttestation.Attestation.Label))
				}
			}
		})
	}
}
