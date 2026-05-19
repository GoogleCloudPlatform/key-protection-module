package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"
)

const defaultTimeout = 10 * time.Second

func main() {
	serverAddr := flag.String("addr", "localhost:50051", "The server address in the format of localhost:port")
	challenge := flag.String("challenge", "default-challenge", "Challenge for attestation")
	handle := flag.String("handle", "default-handle", "Key handle for attestation")
	flag.Parse()

	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req := &pb.GetKeyEndorsementRequest{
		Challenge: []byte(*challenge),
		KeyHandle: &keymanager.KeyHandle{Handle: *handle},
	}

	log.Printf("Sending request to %s with challenge %q and handle %q", *serverAddr, *challenge, *handle)
	resp, err := c.GetKeyEndorsement(ctx, req)
	if err != nil {
		log.Fatalf("could not get key endorsement: %v", err)
	}

	log.Printf("Response received successfully!")
	log.Printf("Response: %+v", resp)
}
