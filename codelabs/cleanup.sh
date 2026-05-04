#!/bin/bash
cd "$(dirname "$0")/.." || exit 1

# Default values
PROJECT_ID=""
ZONE="us-central1-a"
REGION="us-central1"
IMAGE_NAME=""
SA_NAME="secure-inference-sa"
VM_NAME="secure-inference-node"
IG_NAME="secure-inference-ig"
HC_NAME="secure-inference-hc"
BACKEND_NAME="secure-inference-backend"
FW_VLLM_NAME="allow-vllm-ingress"
FW_HC_NAME="allow-hc-ingress"
FWD_RULE_NAME="secure-inference-forwarding-rule"

usage() {
    echo "Usage: $0 --project-id <PROJECT_ID> [OPTIONS]"
    echo "Options:"
    echo "  --zone <ZONE>                  Default: us-central1-a"
    echo "  --region <REGION>              Default: us-central1"
    echo "  --image-name <IMAGE_NAME>      Default: gcr.io/<PROJECT_ID>/secure-vllm:v1"
    echo "  --sa-name <SA_NAME>            Default: secure-inference-sa"
    echo "  --vm-name <VM_NAME>            Default: secure-inference-node"
    echo "  --ig-name <IG_NAME>            Default: secure-inference-ig"
    echo "  --hc-name <HC_NAME>            Default: secure-inference-hc"
    echo "  --backend-name <BACKEND>       Default: secure-inference-backend"
    echo "  --fw-vllm-name <FW_VLLM>       Default: allow-vllm-ingress"
    echo "  --fw-hc-name <FW_HC>           Default: allow-hc-ingress"
    echo "  --fwd-rule-name <FWD_RULE>     Default: secure-inference-forwarding-rule"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project-id) PROJECT_ID="$2"; shift ;;
        --zone) ZONE="$2"; shift ;;
        --region) REGION="$2"; shift ;;
        --image-name) IMAGE_NAME="$2"; shift ;;
        --sa-name) SA_NAME="$2"; shift ;;
        --vm-name) VM_NAME="$2"; shift ;;
        --ig-name) IG_NAME="$2"; shift ;;
        --hc-name) HC_NAME="$2"; shift ;;
        --backend-name) BACKEND_NAME="$2"; shift ;;
        --fw-vllm-name) FW_VLLM_NAME="$2"; shift ;;
        --fw-hc-name) FW_HC_NAME="$2"; shift ;;
        --fwd-rule-name) FWD_RULE_NAME="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

if [ -z "${PROJECT_ID}" ]; then
    echo "ERROR: --project-id is required."
    usage
fi

if [ -z "${IMAGE_NAME}" ]; then
    IMAGE_NAME="gcr.io/${PROJECT_ID}/secure-vllm:v1"
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Deleting Forwarding Rule..."
gcloud compute forwarding-rules delete "${FWD_RULE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet || true

echo "Deleting Backend Service..."
gcloud compute backend-services delete "${BACKEND_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet || true

echo "Deleting Health Check..."
gcloud compute health-checks delete "${HC_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet || true

echo "Deleting Instance Group..."
gcloud compute instance-groups unmanaged delete "${IG_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" --quiet || true

echo "Deleting Firewall Rules..."
gcloud compute firewall-rules delete "${FW_HC_NAME}" --project="${PROJECT_ID}" --quiet || true
gcloud compute firewall-rules delete "${FW_VLLM_NAME}" --project="${PROJECT_ID}" --quiet || true

echo "Deleting Confidential VM..."
gcloud compute instances delete "${VM_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" --quiet || true

# Deleting Service Account...
# echo "Deleting Service Account..."
# gcloud iam service-accounts delete "${SA_EMAIL}" --project="${PROJECT_ID}" --quiet || true

# Try to delete the image from GCR
echo "Deleting Docker Image..."
gcloud container images delete "${IMAGE_NAME}" --force-delete-tags --quiet || true

rm -f .image_hash .lb_ip

echo "Cleanup complete!"
