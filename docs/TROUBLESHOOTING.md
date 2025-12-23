# Troubleshooting Guide

## Common Issues

### 1. SPIRE Server Won't Start

**Symptoms**:
```
Error: failed to dial: connection refused
```

**Solution**:
```bash
# Check if server pod is running
kubectl get pods -n spire -l app=spire-server

# Check logs
kubectl logs -n spire spire-server-0

# Verify ConfigMap
kubectl get configmap -n spire spire-server

# Restart if needed
kubectl delete pod -n spire spire-server-0
```

### 2. SPIRE Agents Not Attesting

**Symptoms**:
```
ERROR: failed to attest node
```

**Solution**:
```bash
# Check agent logs
kubectl logs -n spire -l app=spire-agent

# Verify node attestor config
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server agent list

# Check service account tokens
kubectl get serviceaccount -n spire spire-agent
```

### 3. Certificate Rotation Failures

**Symptoms**:
```
ERROR: certificate expired
ERROR: failed to renew SVID
```

**Solution**:
```bash
# Check SPIRE agent connectivity
kubectl exec -n spire -l app=spire-agent -- \
  /opt/spire/bin/spire-agent api fetch

# Verify workload registration
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show

# Force rotation
kubectl rollout restart deployment pipeline-orchestrator
```

### 4. mTLS Handshake Failures

**Symptoms**:
```
ERROR: certificate verify failed
ERROR: unable to get local issuer certificate
```

**Solution**:
```bash
# Verify SPIRE bundle
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server bundle show

# Check workload SVID
kubectl exec deployment/threat-classifier -- \
  python -c "from pyspiffe.workloadapi import WorkloadApiClient; \
             client = WorkloadApiClient(); \
             svid = client.fetch_x509_svid(); \
             print(svid.spiffe_id)"

# Repair entries if needed
cd scripts
./repair-spire-entries.sh
```

### 5. LLM Gateway Connection Errors

**Symptoms**:
```
ERROR: Failed to connect to LLM gateway
ConnectionRefusedError: [Errno 111] Connection refused
```

**Solution**:
```bash
# Check gateway pod
kubectl get pods -l app=llm-gateway
kubectl logs -l app=llm-gateway

# Verify service
kubectl get svc llm-gateway

# Test connectivity from agent
kubectl exec deployment/threat-classifier -- \
  curl -v https://llm-gateway:5000/health
```

### 6. Gemini API Errors

**Symptoms**:
```
ERROR: API key invalid
ERROR: Rate limit exceeded
```

**Solution**:
```bash
# Verify API key secret
kubectl get secret gemini-api-key -o jsonpath='{.data.api-key}' | base64 -d

# Test API key directly
curl https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"test"}]}]}' \
  -H "x-goog-api-key: YOUR_API_KEY"

# Check rate limits
kubectl logs -l app=llm-gateway | grep "rate limit"
```

### 7. Orchestrator Not Routing Requests

**Symptoms**:
```
ERROR: Failed to reach agent
timeout: no response from classifier
```

**Solution**:
```bash
# Check all agent pods
kubectl get pods -l component=ai-agent

# Verify services
kubectl get svc threat-classifier threat-validator confidence-scorer

# Test individual agent
kubectl port-forward svc/threat-classifier 9001:9001
curl http://localhost:9001/health

# Check orchestrator logs
kubectl logs -l app=pipeline-orchestrator --tail=100
```

### 8. High Latency

**Symptoms**:
```
WARNING: Request took 5000ms
```

**Solution**:
```bash
# Check resource limits
kubectl describe pod -l component=ai-agent

# Increase resources if needed
kubectl edit deployment threat-classifier
# Update:
#   resources:
#     requests:
#       memory: "512Mi"
#       cpu: "500m"

# Scale up replicas
kubectl scale deployment threat-classifier --replicas=3
```

### 9. Missing SPIRE Entries

**Symptoms**:
```
ERROR: no identity issued
WARN: workload not registered
```

**Solution**:
```bash
# List current entries
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show

# Run repair script
cd scripts
./repair-spire-entries.sh

# Verify entries created
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show | grep "SPIFFE ID"
```

### 10. Python Dependency Issues

**Symptoms**:
```
ModuleNotFoundError: No module named 'pyspiffe'
ImportError: cannot import name 'WorkloadApiClient'
```

**Solution**:
```bash
# Rebuild container with correct dependencies
docker build -t your-registry/agent:latest .

# Verify requirements.txt
cat requirements.txt | grep pyspiffe

# Update deployment image
kubectl set image deployment/threat-classifier \
  threat-classifier=your-registry/agent:latest
```

## Debugging Commands

### Check SPIRE Health
```bash
# Server health
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server healthcheck

# Agent health
kubectl exec -n spire -l app=spire-agent -- \
  /opt/spire/bin/spire-agent healthcheck
```

### View All SPIFFE IDs
```bash
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show -selector k8s:ns:default
```

### Test mTLS Connection
```bash
kubectl exec deployment/pipeline-orchestrator -- \
  python -c "
from pyspiffe.workloadapi import WorkloadApiClient
import requests

client = WorkloadApiClient()
svid = client.fetch_x509_svid()
print(f'SVID: {svid.spiffe_id}')
print(f'Expires: {svid.cert.not_valid_after}')
"
```

### Monitor Certificate Rotation
```bash
# Watch SPIRE agent logs
kubectl logs -n spire -l app=spire-agent -f | grep "rotation"

# Monitor workload SVID updates
kubectl logs deployment/threat-classifier -f | grep "SVID updated"
```

## Log Analysis

### Enable Debug Logging

**SPIRE Server**:
```yaml
# In spire-server ConfigMap
log_level = "DEBUG"
```

**SPIRE Agent**:
```yaml
# In spire-agent ConfigMap
log_level = "DEBUG"
```

**Python Agents**:
```python
# Add to agent code
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Key Log Patterns

**Successful mTLS**:
```
INFO: mTLS connection established
INFO: Peer SPIFFE ID: spiffe://k8s.local/ns/default/sa/threat-classifier
```

**Certificate Rotation**:
```
INFO: SVID rotation started
INFO: New SVID received, expires at 2025-01-21T15:30:00Z
INFO: SVID rotation completed
```

**Authentication Failure**:
```
ERROR: certificate verify failed
ERROR: Peer SPIFFE ID not authorized
```

## Performance Monitoring

```bash
# Check pod resources
kubectl top pods

# Monitor SPIRE server
kubectl top pod -n spire spire-server-0

# View metrics
kubectl port-forward -n spire spire-server-0 9988:9988
curl http://localhost:9988/metrics
```

## Support

For additional help:
1. Check [ARCHITECTURE.md](ARCHITECTURE.md) for system design
2. Review [QUICKSTART.md](../QUICKSTART.md) for deployment steps
3. Consult SPIRE documentation: https://spiffe.io/docs/latest/
4. Open an issue in this repository
