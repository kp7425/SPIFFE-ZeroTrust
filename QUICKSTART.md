# Quick Start Guide

## Prerequisites

- Kubernetes cluster (v1.28+)
- kubectl configured
- Python 3.11+
- Google Cloud API Key (Gemini 2.0 Flash)

## 1. Deploy SPIRE Infrastructure

```bash
# Deploy SPIRE server and agents
cd scripts
./deploy-spire.sh

# Verify SPIRE is running
kubectl get pods -n spire
```

## 2. Deploy LLM Gateway

```bash
# Create secret for Gemini API key
kubectl create secret generic gemini-api-key \
  --from-literal=api-key=YOUR_API_KEY_HERE \
  -n default

# Deploy gateway
kubectl apply -f deployments/serviceaccount.yaml
kubectl apply -f deployments/deployment.yaml
kubectl apply -f deployments/service.yaml

# Verify gateway
kubectl get pods -l app=llm-gateway
```

## 3. Deploy AI Agents

```bash
# Deploy all agents
kubectl apply -f configs/ai-agents.yaml
kubectl apply -f configs/pipeline-orchestrator.yaml

# Verify agents
kubectl get pods -l component=ai-agent
```

## 4. Verify mTLS Authentication

```bash
# Check SPIRE entries
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry show

# Test agent communication
kubectl logs -l app=pipeline-orchestrator --tail=50
```

## 5. Test the System

```bash
# Port-forward to orchestrator
kubectl port-forward svc/pipeline-orchestrator 8080:8080

# Send test request
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Test threat analysis"}'
```

## Troubleshooting

### SPIRE Entries Missing
```bash
cd scripts
./repair-spire-entries.sh
```

### Certificate Rotation Issues
Check SPIRE agent logs:
```bash
kubectl logs -n spire -l app=spire-agent
```

### Gateway Connection Errors
Verify Gemini API key:
```bash
kubectl get secret gemini-api-key -o jsonpath='{.data.api-key}' | base64 -d
```

## Architecture

```
┌─────────────────┐     mTLS      ┌──────────────────┐
│  Orchestrator   │◄─────────────►│  LLM Gateway     │
└────────┬────────┘               └────────┬─────────┘
         │ mTLS                            │ HTTPS
         │                                 │
    ┌────▼────────┐                  ┌────▼────────┐
    │  Classifier  │                  │   Gemini    │
    ├─────────────┤                  │  2.0 Flash  │
    │  Validator   │                  └─────────────┘
    ├─────────────┤
    │   Scorer     │
    └─────────────┘
         △
         │ mTLS
    ┌────┴─────┐
    │  SPIRE   │
    └──────────┘
```

## Citation

If you use this code in your research, please cite:

```bibtex
@inproceedings{pappu2025spiffe,
  title={SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems},
  author={Pappu, Karthik and Bhushan, Badal and Mittal, Akshay},
  booktitle={IEEE International Conference on Control and Automation (ICCA)},
  year={2025}
}
```

## License

See [LICENSE](LICENSE) for details.
