#!/bin/bash
set -euo pipefail

PROTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTESTATION_DIR="$(cd "$PROTO_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ATTESTATION_DIR/../.." && pwd)"
export PATH="$(go env GOPATH)/bin:$PATH"

cd "$ATTESTATION_DIR"
go mod download github.com/GoogleCloudPlatform/confidential-space/server github.com/google/go-eventlog

CONFIDENTIAL_SPACE_DIR="$(go list -mod=readonly -m -f '{{.Dir}}' github.com/GoogleCloudPlatform/confidential-space/server)"
EVENTLOG_DIR="$(go list -mod=readonly -m -f '{{.Dir}}' github.com/google/go-eventlog)"
WORKSPACE="$(mktemp -d)"
trap 'rm -rf "$WORKSPACE"' EXIT

mkdir -p "$WORKSPACE/proto" "$WORKSPACE/km_common/proto"
cp "$PROTO_DIR/api.proto" "$WORKSPACE/proto/api.proto"
cp "$REPO_ROOT"/km_common/proto/*.proto "$WORKSPACE/km_common/proto/"
cp "$CONFIDENTIAL_SPACE_DIR/proto/attestation.proto" "$WORKSPACE/attestation.proto"
cp "$EVENTLOG_DIR/proto/state.proto" "$WORKSPACE/proto/state.proto"
cp "$REPO_ROOT/buf.lock" "$WORKSPACE/buf.lock"

cat > "$WORKSPACE/buf.yaml" <<'EOF'
version: v2
modules:
  - path: .
deps:
  - buf.build/bufbuild/protovalidate
lint:
  except:
    - PACKAGE_DIRECTORY_MATCH
    - PACKAGE_VERSION_SUFFIX
EOF

cd "$WORKSPACE"
go run github.com/bufbuild/buf/cmd/buf@v1.68.2 lint --path proto/api.proto
go run github.com/bufbuild/buf/cmd/buf@v1.68.2 generate . --path proto/api.proto --template "$PROTO_DIR/buf.gen.yaml"

test -f gen/api.pb.go
test -f gen/api_grpc.pb.go
install -m 0644 gen/api.pb.go "$PROTO_DIR/gen/api.pb.go"
install -m 0644 gen/api_grpc.pb.go "$PROTO_DIR/gen/api_grpc.pb.go"
