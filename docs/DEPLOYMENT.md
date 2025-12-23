# Deployment Guide

## Prerequisites

### Required Software
- **Kubernetes**: v1.28 or later
- **kubectl**: Configured with cluster access
- **Python**: 3.11 or later
- **Docker**: For building custom images (optional)

### Required Accounts
- **Google Cloud**: Gemini API access
  - Get API key: https://makersuite.google.com/app/apikey
  - Free tier: 60 requests/minute

### Cluster Requirements
- **Nodes**: Minimum 1 node (development) or 3 nodes (production)
- **Memory**: 4GB minimum per node
- **CPU**: 2 cores minimum per node
- **Storage**: 10GB for SPIRE data

## Step-by-Step Deployment

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/spiffe-ai-auth.git
cd spiffe-ai-auth
```

### Step 2: Deploy SPIRE Infrastructure

**2.1 Create SPIRE Namespace**
```bash
kubectl create namespace spire
```

**2.2 Deploy SPIRE Server**
```bash
kubectl apply -f configs/spire-server.yaml
```

**2.3 Wait for Server Ready**
```bash
kubectl wait --for=condition=ready pod -l app=spire-server -n spire --timeout=300s
```

**2.4 Deploy SPIRE Agents**
```bash
kubectl apply -f configs/spire-agent.yaml
```

**2.5 Verify SPIRE Deployment**
```bash
# Check all SPIRE pods are running
kubectl get pods -n spire

# Expected output:
# NAME              READY   STATUS    RESTARTS   AGE
# spire-server-0    1/1     Running   0          2m
# spire-agent-xxx   1/1     Running   0          1m
```

**2.6 Register Workload Identities**
```bash
cd scripts
./deploy-spire.sh
```

This script creates SPIRE entries for:
- Pipeline Orchestrator
- Threat Classifier
- Threat Validator
- Confidence Scorer
- LLM Gateway

**2.7 Verify Entries**
```bash
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show

# You should see 5 entries with SPIFFE IDs like:
# spiffe://k8s.local/ns/default/sa/pipeline-orchestrator
# spiffe://k8s.local/ns/default/sa/threat-classifier
# etc.
```

### Step 3: Deploy LLM Gateway

**3.1 Create Gemini API Key Secret**
```bash
kubectl create secret generic gemini-api-key \
  --from-literal=api-key=YOUR_GEMINI_API_KEY_HERE \
  -n default
```

**3.2 Deploy Gateway**
```bash
# Service account
kubectl apply -f deployments/serviceaccount.yaml

# Deployment
kubectl apply -f deployments/deployment.yaml

# Service
kubectl apply -f deployments/service.yaml
```

**3.3 Verify Gateway**
```bash
kubectl get pods -l app=llm-gateway
kubectl logs -l app=llm-gateway

# Expected log: "LLM Gateway started on port 5000"
```

**3.4 Test Gateway Health**
```bash
kubectl port-forward svc/llm-gateway 5000:5000 &
curl http://localhost:5000/health

# Expected: {"status": "healthy"}
```

### Step 4: Deploy AI Agents

**4.1 Deploy Agents**
```bash
kubectl apply -f configs/ai-agents.yaml
```

This deploys:
- Threat Classifier (port 9001)
- Threat Validator (port 9002)
- Confidence Scorer (port 9003)

**4.2 Deploy Orchestrator**
```bash
kubectl apply -f configs/pipeline-orchestrator.yaml
```

**4.3 Wait for All Agents**
```bash
kubectl wait --for=condition=ready pod -l component=ai-agent --timeout=300s
kubectl wait --for=condition=ready pod -l app=pipeline-orchestrator --timeout=300s
```

**4.4 Verify All Services**
```bash
kubectl get pods -l component=ai-agent
kubectl get pods -l app=pipeline-orchestrator
kubectl get svc

# Expected services:
# threat-classifier      ClusterIP   10.x.x.x   9001
# threat-validator       ClusterIP   10.x.x.x   9002
# confidence-scorer      ClusterIP   10.x.x.x   9003
# pipeline-orchestrator  ClusterIP   10.x.x.x   8080
# llm-gateway           ClusterIP   10.x.x.x   5000
```

### Step 5: Verify mTLS Authentication

**5.1 Check Agent Logs**
```bash
kubectl logs -l app=pipeline-orchestrator --tail=20

# Look for:
# "SVID obtained: spiffe://k8s.local/ns/default/sa/pipeline-orchestrator"
# "mTLS client initialized"
```

**5.2 Verify Certificate Rotation**
```bash
# Watch for rotation events (happens every ~45 minutes)
kubectl logs -l app=threat-classifier -f | grep "SVID"

# You'll see:
# "SVID obtained, expires at ..."
# "SVID rotation initiated"
# "SVID updated successfully"
```

### Step 6: Test the System

**6.1 Port Forward Orchestrator**
```bash
kubectl port-forward svc/pipeline-orchestrator 8080:8080
```

**6.2 Send Test Request**
```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Suspicious PowerShell activity detected with base64 encoded commands"
  }'
```

**6.3 Expected Response**
```json
{
  "classification": {
    "threat_type": "Malicious Code Execution",
    "severity": "high",
    "confidence": 0.92
  },
  "validation": {
    "status": "confirmed",
    "cross_references": ["MITRE ATT&CK T1059.001"]
  },
  "confidence_score": {
    "final_score": 0.89,
    "factors": {
      "llm_confidence": 0.92,
      "validation_confidence": 0.87,
      "behavioral_signals": 0.88
    }
  }
}
```

## Production Deployment

### High Availability

**SPIRE Server HA**
```yaml
# In spire-server.yaml
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
```

**Agent Replicas**
```bash
kubectl scale deployment threat-classifier --replicas=3
kubectl scale deployment threat-validator --replicas=3
kubectl scale deployment confidence-scorer --replicas=3
kubectl scale deployment pipeline-orchestrator --replicas=2
```

### Resource Limits

**Example for Production**
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

### Monitoring

**Deploy Prometheus (Optional)**
```bash
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/bundle.yaml

# SPIRE exports metrics on port 9988
kubectl port-forward -n spire spire-server-0 9988:9988
curl http://localhost:9988/metrics
```

### Security Hardening

**1. Network Policies**
```yaml
# Restrict traffic to only necessary paths
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ai-agent-policy
spec:
  podSelector:
    matchLabels:
      component: ai-agent
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: pipeline-orchestrator
```

**2. Pod Security Standards**
```yaml
# Enable restricted pod security
apiVersion: v1
kind: Namespace
metadata:
  name: default
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

**3. Secret Management**
```bash
# Use external secret manager (e.g., Vault)
# Instead of kubectl create secret, use:
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: gemini-api-key
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: gemini-api-key
  data:
  - secretKey: api-key
    remoteRef:
      key: gemini-api-key
EOF
```

## Validation Checklist

- [ ] All SPIRE pods running (1 server + agents on each node)
- [ ] 5 SPIRE entries registered (verify with `entry show`)
- [ ] LLM Gateway deployed and healthy
- [ ] All 3 AI agents deployed and ready
- [ ] Pipeline orchestrator deployed and ready
- [ ] Test request returns valid response
- [ ] mTLS authentication working (check logs)
- [ ] Certificate rotation working (monitor for 1 hour)
- [ ] Gemini API key valid (test health endpoint)
- [ ] Services accessible within cluster

## Rollback Procedure

If deployment fails:

```bash
# Remove all agents
kubectl delete -f configs/ai-agents.yaml
kubectl delete -f configs/pipeline-orchestrator.yaml

# Remove gateway
kubectl delete -f deployments/

# Remove SPIRE entries
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry delete -spiffeID \
  spiffe://k8s.local/ns/default/sa/pipeline-orchestrator

# Remove SPIRE infrastructure
kubectl delete -f configs/spire-agent.yaml
kubectl delete -f configs/spire-server.yaml

# Remove namespace
kubectl delete namespace spire
```

## Next Steps

1. Review [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design
2. Read [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues
3. Customize agent logic in `agents/` directory
4. Adjust SPIRE TTL in `configs/spire-server.yaml`
5. Scale replicas for production load

## Support

- Issues: Open GitHub issue
- Documentation: https://spiffe.io/docs/
- Gemini API: https://ai.google.dev/docs
