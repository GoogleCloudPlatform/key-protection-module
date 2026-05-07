#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

go mod download github.com/GoogleCloudPlatform/confidential-space/server

protoc -I. -I.. -I../.. \
-I$(go list -mod=readonly -m -f "{{.Dir}}" github.com/GoogleCloudPlatform/confidential-space/server)/proto \
--go_out=proto/gen \
--go_opt=module=github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto \
--go-grpc_out=proto/gen \
--go-grpc_opt=module=github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto \
proto/api.proto
