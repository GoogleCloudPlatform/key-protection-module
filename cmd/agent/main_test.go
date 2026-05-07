package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
)

const (
	pollAttempts = 50
	pollInterval = 100 * time.Millisecond
	testTimeout  = 5 * time.Second
)

func TestRunWSD(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wsd-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	socketPath := filepath.Join(tmpDir, "wsd.sock")

	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- runWSD(ctx, socketPath, keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED)
	}()

	// Wait for the socket file to be created to ensure the server has started
	started := false
	for range pollAttempts {
		if _, err := os.Stat(socketPath); err == nil {
			started = true
			break
		}
		time.Sleep(pollInterval)
	}

	if !started {
		t.Fatalf("Socket file %s was not created in time", socketPath)
	}

	// Trigger clean shutdown
	cancel()

	// Wait for the run function to return
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("runWSD() returned an unexpected error: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("runWSD() did not shut down cleanly in time")
	}
}

func TestRunWSD_InvalidSocketPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create a file so that MkdirAll will fail when trying to use it as a directory
	tmpFile, err := os.CreateTemp("", "not-a-dir")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	socketPath := filepath.Join(tmpFile.Name(), "wsd.sock")

	err = runWSD(ctx, socketPath, keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED)
	if err == nil {
		t.Fatal("Expected runWSD() to return an error for invalid socket path")
	}
}

func TestRunKPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Pick an available port
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to pick an available port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	errChan := make(chan error, 1)
	go func() {
		errChan <- runKPS(ctx, port)
	}()

	// Wait for the server to start by polling the port
	addr := fmt.Sprintf(":%d", port)
	started := false
	for range pollAttempts {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			started = true
			break
		}
		time.Sleep(pollInterval)
	}

	if !started {
		t.Fatalf("KPS server did not start on port %d in time", port)
	}

	// Trigger clean shutdown
	cancel()

	// Wait for the run function to return
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("runKPS() returned an unexpected error: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("runKPS() did not shut down cleanly in time")
	}
}

func TestRunKPS_InvalidPort(t *testing.T) {
	ctx := context.Background()

	// Use an impossible port
	err := runKPS(ctx, -1)
	if err == nil {
		t.Fatal("Expected runKPS() to return an error for invalid port")
	}
}

func TestParseEnvEnum(t *testing.T) {
	key := "TEST_ENV_ENUM"
	enumMap := map[string]int32{
		"VALUE1": 1,
		"VALUE2": 2,
	}
	defaultValue := keymanager.ServiceRole_WSD

	// Test default value
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Failed to unsetenv: %v", err)
	}
	if val := parseEnvEnum(key, defaultValue, enumMap); val != defaultValue {
		t.Errorf("parseEnvEnum() = %v, want %v", val, defaultValue)
	}

	// Test valid value
	if err := os.Setenv(key, "VALUE2"); err != nil {
		t.Fatalf("Failed to setenv: %v", err)
	}
	defer func() {
		if err := os.Unsetenv(key); err != nil {
			t.Errorf("Failed to unsetenv in defer: %v", err)
		}
	}()
	expected := keymanager.ServiceRole(2)
	if val := parseEnvEnum(key, defaultValue, enumMap); val != expected {
		t.Errorf("parseEnvEnum() = %v, want %v", val, expected)
	}
}
