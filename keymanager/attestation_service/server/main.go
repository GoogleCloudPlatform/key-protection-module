// Package main provides an example server for the Attestation Service.
// It opens the TPM and starts a gRPC service to handle attestation requests.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/go-tpm-tools/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	port := flag.String("port", ":50051", "TCP port to listen on")
	kpsAddr := flag.String("kps-address", "127.0.0.1:50050", "Address of the Key Protection Service gRPC server")
	flag.Parse()

	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}
	defer lis.Close()

	ctx := context.Background()
	exps := agent.Experiments{EnableAttestationEvidence: true, BcMode: true}
	attestAgent, err := agent.CreateAttestationAgent(nil, nil, nil, nil, nil, exps, &simpleLogger{}, nil, nil)
	if err != nil {
		log.Fatalf("failed to create attestation agent: %v", err)
	}

	conn, err := grpc.NewClient(*kpsAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to KPS: %v", err)
	}
	defer conn.Close()
	keyClaimsClient := keymanager.NewKeyClaimsServiceClient(conn)

	server := service.New(ctx, lis, attestAgent, keyClaimsClient)

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

	log.Printf("Successfully started Attestation Service at port %s", *port)
}

type simpleLogger struct{}

func (l *simpleLogger) Info(msg string, args ...any) {
	log.Printf("INFO: "+msg, args...)
}

func (l *simpleLogger) Error(msg string, args ...any) {
	log.Printf("ERROR: "+msg, args...)
}
