// package main is the entrypoint for the keymanager workload service daemon.
// TODO: this is currently a placeholder to test a minimum key-manager. A separate PR
// will add the key-protection-agent functionality.
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

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	workloadservice "github.com/GoogleCloudPlatform/key-protection-module/workload_service"
)

func main() {
	socketPath := flag.String("socket", "/run/container_launcher/agent.sock", "Path to the unix socket")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := parseEnvEnum("KEY_PROTECTION_MECHANISM", keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED, keymanager.KeyProtectionMechanism_value)

	log.Printf("Starting Key Protection Agent. Mode: %s\n", mode)

	if err := runWSD(ctx, *socketPath, mode); err != nil {
		log.Fatalf("Agent exited with error: %v", err)
	}
}

func runWSD(ctx context.Context, socketPath string, mode keymanager.KeyProtectionMechanism) error {
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for socket %s: %w", socketDir, err)
	}

	log.Printf("Initializing WSD server on unix socket %s", socketPath)
	srv, err := workloadservice.New(ctx, socketPath, mode)
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
