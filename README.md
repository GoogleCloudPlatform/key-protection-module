# Key Protection Module (KPM)

The Key Protection Module (KPM) provides a secure infrastructure for managing cryptographic keys.

## Project Overview

KPM consists of two primary layers:

- **Key Orchestration Layer (KOL):** Written in **Go**, this layer provides gRPC services for key management and high-level orchestration.
- **Key Custody Core (KCC):** Written in **Rust**, this layer handles sensitive cryptographic operations and key storage in protected memory. It uses **BoringSSL** (via `bssl-crypto`) for underlying cryptography.

The Go layer communicates with the Rust layer via **FFI (Foreign Function Interface)** using CGO.

## Architecture

### Component Breakdown

- `key_protection_service/`: Implements the KPS gRPC service and its corresponding KCC FFI bindings.
- `workload_service/`: Implements the Workload gRPC service and its corresponding KCC FFI bindings.
- `km_common/`: Shared Rust library containing protobuf definitions, cryptographic wrappers, and protected memory management.
- `third_party/bssl-crypto/`: A Rust wrapper for BoringSSL, providing safe cryptographic primitives.
- `boringssl/`: Submodule containing the BoringSSL source code.

## Building and Running

### Prerequisites

- Go 1.24+
- Rust 2024 edition
- `cbindgen` (for generating FFI headers)
- `bindgen-cli` (ensure `$HOME/.cargo/bin` is in your `PATH`)
- `cmake` (for building BoringSSL)
- `buf` (for Go protobuf generation)

### Build Steps

The build process involves generating protobuf code, FFI headers, building the Rust libraries, and then building/testing the Go services.

1. **Generate Protobuf Code:**
   - **Go:**
     ```bash
     ./gen_keymanager.sh
     ```
   - **Rust:** Handled automatically during `cargo build` via `prost-build`.

2. **Generate FFI Headers:**

   ```bash
   ./generate_ffi_headers.sh
   ```

3. **Build Rust Workspace:**

   ```bash
   cargo build --release --workspace
   ```

## Development Conventions

### Code Style

- **Go:** Follow standard Go idioms and `go fmt`.
- **Rust:** Follow standard Rust idioms and `cargo fmt`.

### Testing

- **Go Tests:**

  `go test ./...`

  `go test -tags=integration ./...`

- **Rust Tests:**

  `cargo test`

## How to Contribute

To make a new contribution, please follow these steps:

1. Fork the repository on GitHub.
2. Clone your forked repository with submodules:
   ```shell
   git clone --recurse-submodules <your-forked-repository-url>
   ```
3. Create a new branch for your changes:
   ```shell
   git checkout -b your-feature-branch
   ```
4. Make your changes and ensure tests pass.
5. Commit your changes with a descriptive message.
6. Push your branch and open a Pull Request.

Please ensure all source files include the appropriate copyright and license headers. See [`docs/contributing.md`](https://github.com/GoogleCloudPlatform/key-protection-module/blob/main/docs/contributing.md) for more details.
