#!/bin/bash
# Master Deployment Script for SPIFFE AI Agent Authentication Testing
# Based on IEEE paper: "Eliminating Static API Keys in AI Agent Authentication"

set -e

echo "=========================================="
echo "SPIFFE AI Agent Authentication Setup"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed or not in PATH${NC}"
    echo "Please install kubectl first"
    exit 1
fi

# Check if we have a Kubernetes cluster
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${YELLOW}Warning: No Kubernetes cluster detected${NC}"
    echo "You can still run agents locally for testing"
    echo ""
fi

echo "Step 1: Creating namespace and SPIRE infrastructure"
echo "---------------------------------------------------"

# Create namespace
kubectl create namespace spiffe-research --dry-run=client -o yaml | kubectl apply -f -

# Deploy SPIRE Server
echo "Deploying SPIRE Server (Certificate Authority)..."
kubectl apply -f configs/spire-server.yaml

# Wait for SPIRE Server to be ready
echo "Waiting for SPIRE Server to be ready..."
kubectl wait --for=condition=ready pod -l app=spire-server -n spiffe-research --timeout=120s

# Deploy SPIRE Agent
echo ""
echo "Deploying SPIRE Agent (DaemonSet)..."
kubectl apply -f configs/spire-agent.yaml

# Wait for SPIRE Agent to be ready
echo "Waiting for SPIRE Agent to be ready..."
sleep 10
kubectl wait --for=condition=ready pod -l app=spire-agent -n spiffe-research --timeout=120s

echo ""
echo -e "${GREEN}✓ SPIRE infrastructure deployed successfully${NC}"
echo ""

echo "Step 2: Registering AI Agent Identities"
echo "----------------------------------------"

# Get SPIRE Server pod name
SPIRE_SERVER_POD=$(kubectl get pod -n spiffe-research -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

# Discover the current SPIRE agent parent ID automatically. The agent's SVID
# contains a unique identifier (not always 'default') — listing agent pod logs
# and extracting the calling identity avoids creating entries with the wrong
# parent ID (which produces "no identity issued").
SPIRE_AGENT_POD=$(kubectl get pod -n spiffe-research -l app=spire-agent -o jsonpath='{.items[0].metadata.name}')
AGENT_PARENT_ID=$(kubectl logs -n spiffe-research "$SPIRE_AGENT_POD" | grep -m1 -Eo "spiffe://research.example.org/spire/agent/k8s_psat/demo-cluster/[0-9a-f-]+" || true)
if [ -z "$AGENT_PARENT_ID" ]; then
    echo "WARNING: Failed to extract agent parent ID from spire-agent logs; falling back to wildcard 'default'."
    AGENT_PARENT_ID="spiffe://research.example.org/spire/agent/k8s_psat/demo-cluster/default"
else
    echo "Detected SPIRE agent Parent ID: $AGENT_PARENT_ID"
fi

echo "Registering Threat Classifier identity..."
kubectl exec -n spiffe-research "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://research.example.org/threat-classifier \
    -parentID ${AGENT_PARENT_ID} \
    -selector k8s:ns:spiffe-research \
    -selector k8s:sa:threat-classifier-sa \
    -ttl 1440 || echo "Entry may already exist"

echo "Registering Confidence Scorer identity..."
kubectl exec -n spiffe-research "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://research.example.org/confidence-scorer \
    -parentID ${AGENT_PARENT_ID} \
    -selector k8s:ns:spiffe-research \
    -selector k8s:sa:confidence-scorer-sa \
    -ttl 1440 || echo "Entry may already exist"

echo "Registering Threat Validator identity..."
kubectl exec -n spiffe-research "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://research.example.org/threat-validator \
    -parentID ${AGENT_PARENT_ID} \
    -selector k8s:ns:spiffe-research \
    -selector k8s:sa:threat-validator-sa \
    -ttl 1440 || echo "Entry may already exist"

echo ""
echo -e "${GREEN}✓ AI Agent identities registered${NC}"
echo ""

echo "Step 3: Listing registered entries"
echo "-----------------------------------"
kubectl exec -n spiffe-research "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry show

echo ""
echo "Step 4: Deployment Summary"
echo "--------------------------"
echo "SPIRE Server Status:"
kubectl get pods -n spiffe-research -l app=spire-server
echo ""
echo "SPIRE Agent Status:"
kubectl get pods -n spiffe-research -l app=spire-agent
echo ""

echo "=========================================="
echo -e "${GREEN}Deployment Complete!${NC}"
echo "=========================================="
echo ""
echo "Trust Domain: research.example.org"
echo "Certificate TTL: 5 minutes"
echo "Rotation Interval: 2.5 minutes (50% lifecycle)"
echo ""
echo "Next Steps:"
echo "1. Deploy AI agents: ./scripts/deploy-agents.sh"
echo "2. Run tests: ./scripts/run-tests.sh"
echo ""
echo "To view SPIRE Server logs:"
echo "kubectl logs -n spiffe-research -l app=spire-server -f"
echo ""
echo "To view SPIRE Agent logs:"
echo "kubectl logs -n spiffe-research -l app=spire-agent -f"
echo ""
