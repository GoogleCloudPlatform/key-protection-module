// Package main is the entrypoint for the keymanager workload service daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	keyprotectionservice "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	workloadservice "github.com/GoogleCloudPlatform/key-protection-module/workload_service"
)

const (
	defaultSocketPath = "/run/container_launcher/kmaserver.sock"
	defaultKpsPort    = 50050
)

func main() {
	socketPath := flag.String("socket", defaultSocketPath, "Path to the unix socket")
	kpsPort := flag.Int("kps-port", defaultKpsPort, "Port for the KPS gRPC server")
	kpsVMIP := flag.String("kps-vm-ip", os.Getenv("KPS_IP"), "IP address of the KPS VM (required when KEY_PROTECTION_MECHANISM=KEY_PROTECTION_VM and SERVICE_ROLE=WSD)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := parseEnvEnum("KEY_PROTECTION_MECHANISM", keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED, keymanager.KeyProtectionMechanism_value)
	role := parseEnvEnum("SERVICE_ROLE", keymanager.ServiceRole_SERVICE_ROLE_WSD, keymanager.ServiceRole_value)

	log.Printf("Starting Key Protection Agent. Mode: %s, Role: %s\n", mode, role)

	var err error
	if mode == keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM && role == keymanager.ServiceRole_SERVICE_ROLE_KPS {
		err = runKps(ctx, *kpsPort)
	} else {
		err = runWsd(ctx, *socketPath, mode, *kpsVMIP)
	}

	if err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

func runWsd(ctx context.Context, socketPath string, mode keymanager.KeyProtectionMechanism, kpsVMIP string) error {
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for socket %s: %w", socketDir, err)
	}

	log.Printf("Initializing KeyManager WSD server on unix socket %s", socketPath)
	srv, err := workloadservice.New(ctx, socketPath, mode, kpsVMIP)
	if err != nil {
		return fmt.Errorf("failed to create WSD server: %w", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("unix socket server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down WSD server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error during unix socket shutdown: %w", err)
		}
		return nil
	}
}

func runKps(ctx context.Context, port int) error {
	log.Printf("Initializing Key Protection Service on TCP port %d", port)
	srv, err := keyprotectionservice.NewServer(port)
	if err != nil {
		return fmt.Errorf("failed to create KPS server: %w", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(); err != nil {
			errChan <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down KPS server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error during gRPC shutdown: %w", err)
		}
		return nil
	}
}

func parseEnvEnum[T ~int32](key string, defaultValue T, enumMap map[string]int32) T {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	v, ok := enumMap[val]
	if !ok {
		log.Fatalf("Unrecognized %s: %s", key, val)
	}
	return T(v)
}
