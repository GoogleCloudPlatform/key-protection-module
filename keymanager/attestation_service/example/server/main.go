// Package main provides an example server for the Attestation Service.
// It opens the TPM and starts a gRPC service to handle attestation requests.
package main

import (
	"context"
	"flag"
	"github.com/google/go-tpm-tools/agent"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

func main() {
	port := flag.String("port", ":50051", "TCP port to listen on")
	flag.Parse()

	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}
	defer lis.Close()

	ctx := context.Background()
	exps := agent.Experiments{EnableAttestationEvidence: true}
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		log.Fatalf("failed to open TPM: %v", err)
	}
	defer tpm.Close()

	attestAgent, err := agent.CreateAttestationAgent(tpm, client.GceAttestationKeyECC, nil, nil, nil, exps, &simpleLogger{}, nil, nil)
	if err != nil {
		log.Fatalf("failed to create attestation agent: %v", err)
	}
	server := service.New(ctx, lis, attestAgent)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down server...")
		server.Shutdown(ctx)
	}()

	if err := server.Serve(); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

type simpleLogger struct{}

func (l *simpleLogger) Info(msg string, args ...any) {
	log.Printf("INFO: "+msg, args...)
}

func (l *simpleLogger) Error(msg string, args ...any) {
	log.Printf("ERROR: "+msg, args...)
}
