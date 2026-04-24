package service

import (
	"context"
	"fmt"
	"net"
	"testing"

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

func TestGetKeyEndorsement_GRPC(t *testing.T) {
	expectedEvidence := &attestationpb.VmAttestation{Label: []byte("test-label")}

	tests := []struct {
		name         string
		req          *pb.GetKeyEndorsementRequest
		agentFn      func(_ context.Context, challenge []byte, _ []byte, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error)
		wantCode     codes.Code
		wantEvidence *attestationpb.VmAttestation
	}{
		{
			name: "Success",
			req: &pb.GetKeyEndorsementRequest{
				Challenge: []byte("test-challenge"),
				KeyHandle: &keymanager.KeyHandle{Handle: "test-handle"},
			},
			agentFn: func(_ context.Context, challenge []byte, _ []byte, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
				if string(challenge) != "test-challenge" {
					t.Errorf("expected challenge 'test-challenge', got %q", string(challenge))
				}
				return expectedEvidence, nil
			},
			wantCode:     codes.OK,
			wantEvidence: expectedEvidence,
		},
		{
			name: "MissingChallenge",
			req: &pb.GetKeyEndorsementRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: "test-handle"},
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
				KeyHandle: &keymanager.KeyHandle{Handle: "test-handle"},
			},
			agentFn: func(_ context.Context, challenge []byte, _ []byte, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
				return nil, fmt.Errorf("agent error")
			},
			wantCode: codes.Internal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &mockAgent{
				attestationEvidenceFn: tc.agentFn,
			}

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}

			server := New(t.Context(), lis, mock)
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

			resp, err := client.GetKeyEndorsement(t.Context(), tc.req)

			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected status code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
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
