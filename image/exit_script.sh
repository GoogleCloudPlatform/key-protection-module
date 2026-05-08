#!/usr/bin/env bash
set -e

if [ -f /usr/share/oem/kps/image.env ]; then
    source /usr/share/oem/kps/image.env
else
    echo "Error: Config file not found!"
    exit 1
fi


if ctr task ls | grep -q "$CONTAINER_NAME"; then
    echo "Stopping running task for $CONTAINER_NAME..."
    
    ctr task kill -s SIGTERM "$CONTAINER_NAME" || true
    
    sleep 5
    
    echo "Deleting the task..."
    ctr task rm -f "$CONTAINER_NAME" || true
else
    echo "No active task found for $CONTAINER_NAME."
fi


if ctr container info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Removing container $CONTAINER_NAME..."
    ctr container rm "$CONTAINER_NAME"
fi
