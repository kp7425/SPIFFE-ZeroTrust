#!/usr/bin/env bash
# Repair SPIRE registration entries for the AI agents
# - Detect the real SPIRE agent parent ID
# - Show existing entries for the agents, and if parentID mismatches, delete + recreate

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! command -v kubectl &> /dev/null; then
  echo "kubectl not found in PATH"
  exit 1
fi

NAMESPACE=${NAMESPACE:-spiffe-research}

echo "Discovering SPIRE server and agent pods in namespace: $NAMESPACE"
SPIRE_SERVER_POD=$(kubectl get pod -n "$NAMESPACE" -l app=spire-server -o jsonpath='{.items[0].metadata.name}')
SPIRE_AGENT_POD=$(kubectl get pod -n "$NAMESPACE" -l app=spire-agent -o jsonpath='{.items[0].metadata.name}')

echo "Server pod: $SPIRE_SERVER_POD"
echo "Agent pod:  $SPIRE_AGENT_POD"

echo "Extracting agent parent ID from spire-agent logs (first match)"
AGENT_PARENT_ID=$(kubectl logs -n "$NAMESPACE" "$SPIRE_AGENT_POD" | grep -m1 -Eo "spiffe://[a-z0-9.-]+/spire/agent/[a-zA-Z0-9_/-]+/[0-9a-f-]+" || true)
if [ -z "$AGENT_PARENT_ID" ]; then
  echo "Failed to extract a parent ID from agent logs; falling back to 'default' parent ID"
  AGENT_PARENT_ID="spiffe://research.example.org/spire/agent/k8s_psat/demo-cluster/default"
fi

echo "Detected AGENT_PARENT_ID: $AGENT_PARENT_ID"

AGENTS=(threat-classifier confidence-scorer threat-validator)

for agent in "${AGENTS[@]}"; do
  echo "\nProcessing registration for agent: $agent"

  # Show existing entry lines for this agent
  echo "Existing entries (server):"
  kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry show | awk -v ag="$agent" 'BEGIN{ins=0}/SPIFFE ID/{if($0 ~ ag) ins=1}ins{print} /─/{if(ins) exit}' || true

  # Get the entry ID associated with this SPIFFE ID if present
  ENTRY_ID=$(kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry show | grep -n "SPIFFE ID\s*:\s*spiffe://research.example.org/$agent" -B2 | grep -Eo "[0-9a-f\-]{36}" | head -n1 || true)

  if [ -z "$ENTRY_ID" ]; then
    echo "No existing registration entry found for $agent — creating a new one with parent $AGENT_PARENT_ID"
    kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry create -spiffeID "spiffe://research.example.org/$agent" -parentID "$AGENT_PARENT_ID" -selector k8s:ns:$NAMESPACE -selector k8s:sa:${agent}-sa -ttl 1440 || echo "Failed to create entry (maybe it already exists)"
    continue
  fi

  echo "Found entry ID: $ENTRY_ID — checking parent"
  CURRENT_PARENT=$(kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry show -id "$ENTRY_ID" | grep "Parent ID" | awk -F":" '{print $2}' | sed -E 's/^\s+//') || true

  if [ -z "$CURRENT_PARENT" ]; then
    echo "Unable to read current parent for entry $ENTRY_ID — skipping"
    continue
  fi

  echo "Current Parent ID: $CURRENT_PARENT"

  if [ "$CURRENT_PARENT" = "$AGENT_PARENT_ID" ]; then
    echo "Parent is already correct — no action needed for $agent"
  else
    echo "Parent differs — re-creating entry for $agent with parent $AGENT_PARENT_ID"
    echo "Deleting entry $ENTRY_ID"
    kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry delete -id "$ENTRY_ID" || echo "Failed to delete entry $ENTRY_ID"

    echo "Creating new entry for $agent"
    kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry create -spiffeID "spiffe://research.example.org/$agent" -parentID "$AGENT_PARENT_ID" -selector k8s:ns:$NAMESPACE -selector k8s:sa:${agent}-sa -ttl 1440 || echo "Failed to create new entry for $agent"
  fi
done

echo "\nRepair completed — list entries to verify:"
kubectl exec -n "$NAMESPACE" "$SPIRE_SERVER_POD" -- /opt/spire/bin/spire-server entry show

echo "\nYou may now delete and re-start agent pods to ensure they receive new SVIDs"
echo "Example: kubectl delete pod -n $NAMESPACE -l app=spire-agent && kubectl delete pod -n $NAMESPACE -l app=threat-classifier"
