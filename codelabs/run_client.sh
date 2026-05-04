#!/bin/bash
set -e
cd "$(dirname "$0")/.."

if [ -z "$1" ]; then
    echo "Usage: $0 <PROJECT_ID> [ZONE]"
    exit 1
fi
PROJECT_ID="$1"
ZONE="${2:-us-central1-a}"

if [ ! -f .image_hash ] || [ ! -f .lb_ip ]; then
    echo "Could not find .image_hash or .lb_ip. Please run setup.sh first, or manually create these files."
    exit 1
fi

IMAGE_HASH=$(cat .image_hash)
LB_IP=$(cat .lb_ip)

echo "Running test client..."
PYTHONPATH=src python3 examples/test_client.py \
    --image-hash "${IMAGE_HASH}" \
    --project-id "${PROJECT_ID}" \
    --zone "${ZONE}" \
    --ip "${LB_IP}" \
    --hw-model "TDX"
