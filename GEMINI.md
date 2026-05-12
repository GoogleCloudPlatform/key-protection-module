# Key Protection Module (KPM)

The Key Protection Module (KPM) provides a secure infrastructure for managing cryptographic keys, separating high-level orchestration from low-level secure custody.

## Project Overview

KPM consists of two primary layers:
- **Key Orchestration Layer (KOL):** Written in **Go**, this layer provides gRPC services for key management and high-level orchestration.
- **Key Custody Core (KCC):** Written in **Rust**, this layer handles sensitive cryptographic operations and key storage in protected memory. It uses **BoringSSL** (via `bssl-crypto`) for underlying cryptography.

The Go layer communicates with the Rust layer via **FFI (Foreign Function Interface)** using CGO.

## Architecture

### Component Breakdown
- `cmd/agent/`: The main entry point for the KPM agent, which runs both the Key Protection Service and the Workload Service.
- `key_protection_service/`: Implements the KPS gRPC service and its corresponding KCC FFI bindings.
- `workload_service/`: Implements the Workload gRPC service and its corresponding KCC FFI bindings.
- `km_common/`: Shared Rust library containing:
    - Protobuf definitions (using `prost`).
    - Cryptographic wrappers.
    - Protected memory management.
    - Common FFI utilities.
- `third_party/bssl-crypto/`: A Rust wrapper for BoringSSL, providing safe cryptographic primitives.
- `image/`: Systemd service files and scripts for running KPM in a production-like environment.

### Communication Flow
1. A gRPC request arrives at one of the Go services.
2. The Go service validates the request and prepares data for the Rust KCC.
3. The Go service calls the Rust FFI functions via CGO.
4. The Rust KCC performs secure operations (e.g., KEM decapsulation, resealing).
5. Results are returned to Go and then back to the gRPC client.

## Building and Running

### Prerequisites
- Go 1.24+
- Rust 2024 edition (or compatible)
- `cbindgen` (for generating FFI headers)
- `bindgen-cli`
- `cmake` (for building BoringSSL)
- BoringSSL dependencies (libssl-dev, etc.)

### Build Steps
The build process involves generating FFI headers, building the Rust libraries, and then building the Go agent.

1. **Generate FFI Headers:**
   ```bash
   ./generate_ffi_headers.sh
   ```

2. **Build Rust Workspace:**
   ```bash
   cargo build --release --workspace
   ```

3. **Build Go Agent:**
   Ensure `CGO_LDFLAGS` points to the Rust build artifacts.
   ```bash
   export CGO_ENABLED=1
   export CGO_LDFLAGS="-L$(pwd)/target/release"
   go build -o kpm-agent ./cmd/agent
   ```

### Using Docker
You can build the entire project using the provided `Dockerfile`:
```bash
docker build -t kpm-agent .
```

## Development Conventions

### Code Style
- **Go:** Follow standard Go idioms and `go fmt`.
- **Rust:** Follow standard Rust idioms and `cargo fmt`.

### Testing
- **Go Tests:**
  ```bash
  go test ./...
  ```
- **Rust Tests:**
  ```bash
  cargo test
  ```
- **Integration Tests:** Integration tests are located in `tests/` and can be run using the `Dockerfile.test`.

### FFI Management
- FFI headers are generated using `cbindgen` and stored in `include/` directories within each service's `key_custody_core` folder.
- Always run `./generate_ffi_headers.sh` after modifying Rust structs or functions exported to C.

### Protobuf
- Protobuf files are located in `km_common/proto/` and service-specific `proto/` directories.
- Rust code uses `prost-build` (see `km_common/build.rs`) to generate Rust code from these protos.
- Go code uses standard `protoc` or `buf` generation (see `buf.gen.yaml`).
