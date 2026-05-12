#!/usr/bin/env bash
set -e

if [ -f /usr/share/oem/kps/image.env ]; then
    source /usr/share/oem/kps/image.env
else
    echo "Error: Config file not found!"
    exit 1
fi

echo "=== Launching Key Protection Agent Container ==="


echo "Importing image from ${IMAGE_PATH}..."
if [ -f "$IMAGE_PATH" ]; then
    ctr images import "$IMAGE_PATH"
else
    echo "Error: Image file not found at $IMAGE_PATH"
    exit 1
fi

echo "Checking for existing container..."
if ctr container info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Removing existing container..."
    ctr container rm "$CONTAINER_NAME"
fi

ctr run --rm -net-host --mount "type=bind,src=/tmp/container_launcher/,dst=/run/container_launcher/,options=rbind:rw" --env SERVICE_ROLE="KPS" --env KEY_PROTECTION_MECHANISM="KEY_PROTECTION_VM" "$IMAGE_REF" "$CONTAINER_NAME"