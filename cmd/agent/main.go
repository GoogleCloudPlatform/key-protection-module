// Package main is the entrypoint for the keymanager workload service daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if role == keymanager.ServiceRole_SERVICE_ROLE_KPS {
		logger = logger.With("service.name", "kps")
	} else {
		logger = logger.With("service.name", "wsd")
	}
	slog.SetDefault(logger)

	slog.Info("Starting Key Protection Agent", "mode", mode.String(), "role", role.String())

	var err error
	if mode == keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM && role == keymanager.ServiceRole_SERVICE_ROLE_KPS {
		err = runKps(ctx, *kpsPort, mode, role)
	} else {
		err = runWsd(ctx, *socketPath, mode, *kpsVMIP)
	}

	if err != nil {
		slog.Error("Server exited with error", "error", err)
		os.Exit(1)
	}
}

func runWsd(ctx context.Context, socketPath string, mode keymanager.KeyProtectionMechanism, kpsVMIP string) error {
	socketDir := filepath.Dir(socketPath)
	// We use 0777 permissions for the socket directory to allow cross-group access
	// so that other workloads/containers running under different GIDs can traverse
	// the directory and connect to the unix socket.
	if err := os.MkdirAll(socketDir, 0777); err != nil { //nolint:gosec
		return fmt.Errorf("failed to create directory for socket %s: %w", socketDir, err)
	}
	if err := os.Chmod(socketDir, 0777); err != nil { //nolint:gosec
		return fmt.Errorf("failed to chmod socket directory %s: %w", socketDir, err)
	}

	slog.Info("Initializing KeyManager WSD server", "socket", socketPath)
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
		slog.Info("Shutting down WSD server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error during unix socket shutdown: %w", err)
		}
		return nil
	}
}

func runKps(ctx context.Context, port int, mode keymanager.KeyProtectionMechanism, role keymanager.ServiceRole) error {
	slog.Info("Initializing Key Protection Service", "port", port)
	srv, err := keyprotectionservice.NewServer(port, mode, role)
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
		slog.Info("Shutting down KPS server...")
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
		slog.Error("Unrecognized enum", "key", key, "value", val)
		os.Exit(1)
	}
	return T(v)
}
