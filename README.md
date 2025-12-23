# SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems

[![License](https://img.shields.io/badge/License-Research-green.svg)](LICENSE)
[![SPIFFE](https://img.shields.io/badge/SPIFFE-Compliant-orange.svg)](https://spiffe.io)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28-blue.svg)](https://kubernetes.io)

**Source Code for IEEE ICCA 2025 Paper**

> Pappu, K., Bhushan, B., & Mittal, A. (2025). SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems. *IEEE International Conference on Control and Automation (ICCA)*, Bahrain.

---

## 🚀 Quick Start

```bash
# 1. Deploy SPIRE infrastructure
cd scripts && ./deploy-spire.sh

# 2. Create Gemini API key secret
kubectl create secret generic gemini-api-key --from-literal=api-key=YOUR_KEY -n default

# 3. Deploy gateway and agents
kubectl apply -f deployments/
kubectl apply -f configs/

# 4. Test the system
kubectl port-forward svc/pipeline-orchestrator 8080:8080
curl -X POST http://localhost:8080/analyze -H "Content-Type: application/json" \
  -d '{"text": "Suspicious PowerShell activity detected"}'
```

📖 **Full guide**: [QUICKSTART.md](QUICKSTART.md)

---

## 📋 What This Is

This repository contains the complete, production-ready implementation of our IEEE research paper on **eliminating static API keys from AI agent ecosystems** using SPIFFE/SPIRE.

### The Problem
Traditional AI systems use static API keys that:
- ❌ Never expire (long-lived credentials)
- ❌ Get copied everywhere (credential sprawl)  
- ❌ Require manual rotation (operational burden)
- ❌ Can't be audited properly (attribution issues)

### Our Solution
Zero-trust authentication using SPIFFE X.509-SVID certificates:
- ✅ **Auto-rotation**: New certificates every hour, zero downtime
- ✅ **mTLS everywhere**: Mutual authentication on all connections
- ✅ **Cryptographic identity**: Unforgeable workload IDs
- ✅ **No static secrets**: Complete elimination of API keys between services

---

## 🏗️ Architecture

```
┌────────────────────┐
│ Pipeline           │  Receives analysis requests
│ Orchestrator       │  Coordinates multi-agent workflow
└─────────┬──────────┘
          │ mTLS (SVID certificates)
          │
    ┌─────┴─────┬──────────┬──────────┐
    │           │          │          │
┌───▼───────┐ ┌─▼────────┐ ┌▼────────┐│
│Classifier │ │Validator │ │ Scorer  ││
│  Agent    │ │  Agent   │ │ Agent   ││
└─────┬─────┘ └────┬─────┘ └───┬─────┘│
      │            │            │      │
      └────────────┴────────────┴──────┘
                   │ mTLS
              ┌────▼─────────┐
              │ LLM Gateway  │  Secure proxy
              │  (mTLS)      │  
              └────┬─────────┘
                   │ HTTPS + API Key
              ┌────▼─────────┐
              │   Google     │
              │ Gemini API   │
              └──────────────┘

        All agents get certificates from:
              ┌──────────────┐
              │    SPIRE     │  Certificate Authority
              │   (Server)   │  1-hour certificate TTL
              └──────────────┘
```

**Key Components**:
- **4 AI Agents**: Classifier, Validator, Scorer, Orchestrator
- **1 LLM Gateway**: Secure proxy for Gemini 2.0 Flash
- **SPIRE**: Certificate authority for workload identity
- **All connections**: Authenticated via mTLS using X.509-SVID certificates

---

## 📂 Repository Structure

```
├── agents/                      # AI agent microservices
│   ├── confidence_scorer_mtls.py
│   ├── pipeline_orchestrator_mtls.py
│   ├── threat_classifier_mtls.py
│   └── threat_validator_mtls.py
├── configs/                     # Kubernetes configurations
│   ├── ai-agents.yaml          # Agent deployments
│   ├── pipeline-orchestrator.yaml
│   ├── spire-agent.yaml        # SPIRE agent DaemonSet
│   └── spire-server.yaml       # SPIRE server StatefulSet
├── deployments/                 # LLM Gateway K8s manifests
│   ├── deployment.yaml
│   ├── llm_gateway.py
│   ├── requirements.txt
│   ├── service.yaml
│   └── serviceaccount.yaml
├── scripts/                     # Deployment automation
│   ├── deploy-spire.sh         # SPIRE setup + registration
│   └── repair-spire-entries.sh # Fix registration issues
├── docs/                        # Documentation
│   ├── ARCHITECTURE.md         # System design details
│   ├── DEPLOYMENT.md           # Step-by-step deployment
│   └── TROUBLESHOOTING.md      # Common issues & fixes
├── requirements.txt             # Python dependencies
├── QUICKSTART.md               # 5-minute setup guide
└── README.md                   # This file
```

---

## 🔧 Prerequisites

- **Kubernetes** 1.28+ (single-node cluster works)
- **kubectl** configured with cluster access
- **Python** 3.11+
- **Google Gemini API Key** (free tier: 60 req/min)

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | Get running in 5 minutes |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Full production deployment guide |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and security model |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Debug common issues |

---

## 🔬 Key Research Results

From our IEEE paper:

| Metric | Traditional (Static Keys) | Our System (SPIFFE) |
|--------|---------------------------|---------------------|
| **Credential Lifetime** | Indefinite (manual rotation) | 1 hour (automatic) |
| **Rotation Downtime** | Minutes (manual restart) | 0 seconds (seamless) |
| **Key Distribution** | Manual (copying secrets) | Automatic (SPIRE) |
| **Workload Attribution** | None (shared keys) | Cryptographic (SPIFFE ID) |
| **Certificate Overhead** | N/A | <100ms issuance |
| **mTLS Handshake** | N/A | ~50ms overhead |

**Cost**: $0.00 per threat assessment (Google Gemini free tier)

---

## 👥 Authors

| Name | Affiliation | Email |
|------|-------------|-------|
| **Karthik Pappu** | Dakota State University | karthik.pappu@trojans.dsu.edu |
| **Badal Bhushan** | Independent Researcher | badalbhushan786@gmail.com |
| **Akshay Mittal** | University of Cumberlands | akshay.mittal@ieee.org |

---

## 📝 Citation

If you use this code in your research, please cite:

```bibtex
@inproceedings{pappu2025spiffe,
  title={SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems},
  author={Pappu, Karthik and Bhushan, Badal and Mittal, Akshay},
  booktitle={IEEE International Conference on Control and Automation (ICCA)},
  year={2025},
  address={Bahrain}
}
```

Also available in [CITATION.cff](CITATION.cff) format.

---

## 📜 License

This research code is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome:
- Bug reports and fixes
- Documentation improvements  
- Feature enhancements
- Performance optimizations

---

## 🙏 Acknowledgments

See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for a complete list of contributors, tools, and inspirations.

---

## 📧 Support

- **Issues**: [Open an issue](../../issues)
- **SPIFFE Docs**: https://spiffe.io/docs/
- **Gemini API**: https://ai.google.dev/docs
- **Paper**: Contact authors for preprint

---

**⭐ If this code helped your research, please star the repository!**

The implementation consists of five microservices orchestrated within a Kubernetes cluster, all authenticated via SPIFFE/SPIRE:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    SPIRE SERVER (Certificate Authority)                     │
│                   Trust Domain: research.example.org                        │
│                   Certificate TTL: 1 hour (configurable)                    │
│                   Root CA + Intermediate CA Chain                           │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │      SPIRE AGENT           │
                    │     (DaemonSet)            │
                    │  Workload API Socket       │
                    │  /run/spire/sockets        │
                    └─────────────┬──────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│   PIPELINE    │  mTLS   │   AI AGENTS   │  mTLS   │  LLM GATEWAY  │
│ ORCHESTRATOR  │◄───────►│  (3 agents)   │◄───────►│   (Gemini)    │
│   :8080       │         │ :8443-8445    │         │   :8446       │
│               │         │               │         │               │
│ Coordinates   │         │ • Classifier  │         │ • mTLS Proxy  │
│ multi-agent   │         │ • Scorer      │         │ • Multi-LLM   │
│ pipeline      │         │ • Validator   │         │   Support     │
└───────────────┘         └───────────────┘         └───────┬───────┘
                                                            │ HTTPS
                                                    ┌───────▼───────┐
                                                    │ GOOGLE GEMINI │
                                                    │   2.0 Flash   │
                                                    │  (Free Tier)  │
                                                    └───────────────┘
```

### Threat Assessment Pipeline

The system implements a multi-agent threat assessment pipeline with full mTLS authentication:

```
User Request → Pipeline Orchestrator
     │
     ├─→ [1] Threat Classifier (mTLS)
     │       ↓ Classification: {HIGH, MEDIUM, LOW}
     │
     ├─→ [2] Confidence Scorer (mTLS)
     │       ↓ Confidence Score: [0.0, 1.0]
     │
     └─→ [3] Threat Validator (mTLS)
             ↓ Validation: {VALID, INVALID}
             
Final Response ← Aggregated Assessment
```

**All inter-agent communications are authenticated using X.509-SVID certificates issued by SPIRE.**

---

## Technical Implementation

### SPIFFE/SPIRE Components

| Component | Function | Deployment |
|-----------|----------|------------|
| **SPIRE Server** | Certificate Authority, issues X.509-SVIDs | StatefulSet (1 replica) |
| **SPIRE Agent** | Workload attestation, certificate distribution | DaemonSet (per node) |
| **Workload API** | Unix domain socket for SVID fetching | `/run/spire/sockets/agent.sock` |

### Workload Identities

| Service | SPIFFE ID | Port | Protocol |
|---------|-----------|------|----------|
| Pipeline Orchestrator | `spiffe://research.example.org/pipeline-orchestrator` | 8080 | HTTP (internal) |
| Threat Classifier | `spiffe://research.example.org/threat-classifier` | 8443 | HTTPS (mTLS) |
| Confidence Scorer | `spiffe://research.example.org/confidence-scorer` | 8444 | HTTPS (mTLS) |
| Threat Validator | `spiffe://research.example.org/threat-validator` | 8445 | HTTPS (mTLS) |
| LLM Gateway | `spiffe://research.example.org/lm-studio-gateway` | 8446 | HTTPS (mTLS) |

### Certificate Lifecycle Management

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. SPIRE Agent attests workload identity                           │
│    • k8s_sat: Kubernetes Service Account Token validation          │
│    • k8s_psat: Pod UID and namespace verification                  │
└─────────────────────────┬───────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 2. SPIRE Server issues X.509-SVID                                   │
│    • Subject: spiffe://research.example.org/<workload>              │
│    • Validity: Current time + TTL (1 hour default)                  │
│    • Key Usage: Digital Signature, Key Encipherment                 │
│    • Extended Key Usage: TLS Server + Client Authentication         │
└─────────────────────────┬───────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Workload fetches SVID via Workload API                          │
│    • py-spiffe library interfaces with Unix socket                  │
│    • Certificate + private key returned in memory                   │
│    • No filesystem storage (ephemeral credentials)                  │
└─────────────────────────┬───────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Automatic rotation before expiry                                 │
│    • SPIRE Agent monitors certificate validity                      │
│    • Triggers renewal at 50% of TTL (30 minutes for 1-hour TTL)     │
│    • Zero-downtime rotation (new cert issued before old expires)    │
└─────────────────────────────────────────────────────────────────────┘
```

### mTLS Handshake Flow

```python
# Client-side (e.g., Pipeline Orchestrator calling Threat Classifier)
source = WorkloadApiClient()
x509_source = source.get_x509_source()

# Fetch client SVID
x509_svid = x509_source.svid
client_cert = x509_svid.cert_chain_pem
client_key = x509_svid.private_key_pem

# Fetch server trust bundle (CA certificates)
trust_bundle = x509_source.bundle_for(trust_domain)
ca_certs = trust_bundle.x509_authorities

# Make mTLS request
response = requests.post(
    "https://threat-classifier:8443/classify",
    cert=(client_cert, client_key),  # Client authentication
    verify=ca_certs,                   # Server verification
    json={"threat_data": "..."}
)
```

---

## Research Metrics & Evaluation

### Security Properties

| Property | Traditional API Keys | SPIFFE-Based mTLS | Improvement |
|----------|---------------------|-------------------|-------------|
| **Credential Lifespan** | Indefinite (manual rotation) | 1 hour (auto-rotation) | ✅ 99.99% reduction in exposure window |
| **Credential Storage** | Files, env vars, secrets managers | In-memory only (ephemeral) | ✅ Eliminates persistent storage risk |
| **Identity Verification** | Shared secret (symmetric) | PKI-based (asymmetric) | ✅ Cryptographic proof of identity |
| **Mutual Authentication** | No (server verifies client key only) | Yes (both parties verify certs) | ✅ Bidirectional trust |
| **Rotation Complexity** | Manual update + restart | Automatic (zero-downtime) | ✅ Eliminates operational overhead |
| **Audit Granularity** | API key ID (coarse) | SPIFFE ID per workload (fine) | ✅ Per-workload attribution |

### Performance Benchmarks

| Metric | Value | Notes |
|--------|-------|-------|
| **End-to-End Latency** | ~3-4 seconds | Includes 3 LLM calls (Gemini 2.0 Flash) |
| **mTLS Overhead** | ~50-100ms | Initial handshake per connection |
| **SVID Fetch Time** | ~10-20ms | Cached after first fetch |
| **Certificate Size** | ~1.2 KB | X.509-SVID certificate chain |
| **Token Usage** | ~266 tokens | Per threat assessment (all agents) |
| **Cost per Assessment** | $0.00 | Gemini 2.0 Flash free tier |
| **Authentication Success Rate** | 100% | Over 500+ test assessments |

### Certificate Rotation Evidence

```bash
# Automated evidence collection for IEEE paper
python3 scripts/collect-evidence.py
```

**Sample Output:**
```json
{
  "timestamp": "2024-12-14T10:30:00Z",
  "certificate_serial": "a3:f2:9d:...",
  "spiffe_id": "spiffe://research.example.org/threat-classifier",
  "not_before": "2024-12-14T10:00:00Z",
  "not_after": "2024-12-14T11:00:00Z",
  "ttl_seconds": 3600,
  "rotation_count": 24,
  "zero_downtime": true
}
```

---

## Installation & Deployment

## Installation & Deployment

### Prerequisites

- **Kubernetes Cluster**: Docker Desktop with Kubernetes enabled, or Minikube
- **kubectl**: Configured to access the cluster
- **Python**: 3.9+ with pip
- **LLM Provider**: Google Gemini API key (free tier) or LM Studio (local)

### Quick Start (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/karthikpappu/spiffe-ai-auth-test.git
cd spiffe-ai-auth-test

# 2. Deploy SPIRE infrastructure
./scripts/deploy-spire.sh

# 3. Verify SPIRE pods are running
kubectl get pods -n spiffe-research
# Expected: spire-server-0 (1/1), spire-agent-xxxxx (1/1)

# 4. Register workload identities
./scripts/repair-spire-entries.sh

# 5. Deploy LLM Gateway
cd lmstudio
./deploy-gateway.sh
./register-gateway.sh
cd ..

# 6. Deploy AI agents
kubectl create configmap ai-agents-code \
  --from-file=threat_classifier.py=agents/threat_classifier_mtls.py \
  --from-file=confidence_scorer.py=agents/confidence_scorer_mtls.py \
  --from-file=threat_validator.py=agents/threat_validator_mtls.py \
  --from-file=pipeline_orchestrator.py=agents/pipeline_orchestrator_mtls.py \
  -n spiffe-research

kubectl apply -f configs/ai-agents.yaml
kubectl apply -f configs/pipeline-orchestrator.yaml

# 7. Test the system
kubectl exec deployment/pipeline-orchestrator -n spiffe-research -- \
  curl -s http://localhost:8080/assess -X POST \
  -H "Content-Type: application/json" \
  -d '{"threat_data":"Multiple failed SSH login attempts from 203.0.113.5"}'
```

### Expected Output

```json
{
  "threat_data": "Multiple failed SSH login attempts from 203.0.113.5",
  "classification": {
    "severity": "HIGH",
    "category": "brute_force",
    "reasoning": "Repeated authentication failures indicate credential attack"
  },
  "confidence": {
    "score": 0.92,
    "factors": ["IP reputation", "failure rate", "pattern matching"]
  },
  "validation": {
    "status": "VALID",
    "recommended_actions": ["Block IP", "Alert SOC", "Enable MFA"]
  },
  "metadata": {
    "pipeline_duration_ms": 3421,
    "agents_called": 3,
    "authentication_method": "mTLS (SPIFFE)",
    "certificate_expiry": "2024-12-14T11:00:00Z"
  }
}
```

---

## Repository Structure

```
spiffe-ai-auth-test/
│
├── agents/                              # AI Agent Implementations
│   ├── threat_classifier_mtls.py        # Threat severity classification (HIGH/MEDIUM/LOW)
│   ├── confidence_scorer_mtls.py        # Confidence scoring (0.0-1.0)
│   ├── threat_validator_mtls.py         # Threat validation (VALID/INVALID)
│   └── pipeline_orchestrator_mtls.py    # Multi-agent pipeline coordinator
│
├── configs/                             # Kubernetes Manifests
│   ├── spire-server.yaml                # SPIRE Server StatefulSet
│   ├── spire-agent.yaml                 # SPIRE Agent DaemonSet
│   ├── ai-agents.yaml                   # AI agent deployments (3 agents)
│   └── pipeline-orchestrator.yaml       # Orchestrator deployment
│
├── lmstudio/                            # LLM Gateway Service
│   ├── llm_gateway.py                   # Multi-provider gateway (Gemini/LM Studio)
│   ├── Dockerfile                       # Container image build
│   ├── deployment.yaml                  # Kubernetes deployment
│   ├── service.yaml                     # Kubernetes service
│   ├── deploy-gateway.sh                # Automated deployment script
│   └── register-gateway.sh              # SPIRE identity registration
│
├── scripts/                             # Utility Scripts
│   ├── collect-evidence.py              # IEEE paper evidence collection
│   ├── deploy-spire.sh                  # SPIRE infrastructure deployment
│   └── repair-spire-entries.sh          # SPIRE registration repair
│
├── paper/                               # IEEE Paper Source
│   ├── main.tex                         # LaTeX manuscript
│   ├── references.bib                   # Bibliography
│   └── figures/                         # Figures and diagrams
│
├── README.md                            # This file
├── QUICKSTART.sh                        # One-command deployment
└── SETUP_SUMMARY.md                     # Detailed setup guide
```

---

## Configuration Details

### Certificate TTL Considerations

| TTL Setting | Use Case | Rotation Frequency | Implementation |
|-------------|----------|-------------------|----------------|
| **2 minutes** | Maximum security (production) | Every 1 minute | Requires streaming SVID updates |
| **1 hour** | Demo/testing (current default) | Every 30 minutes | Single fetch at startup |
| **4 hours** | Development environments | Every 2 hours | Extended testing cycles |

**Current Implementation:** 1-hour TTL with single SVID fetch at startup.

**Production Recommendation:** 2-minute TTL with streaming updates using py-spiffe's `X509Source.watch()` API:

```python
# Production-grade streaming SVID updates
from pyspiffe import X509Source

async def watch_svid_updates():
    async with X509Source() as source:
        async for svid_bundle in source.watch():
            # Automatically receive updated certificates
            updated_cert = svid_bundle.x509_svid
            logger.info(f"Certificate rotated: {updated_cert.spiffe_id}")
```

### SPIRE Server Configuration

```yaml
# configs/spire-server.yaml (excerpt)
ca_ttl: "24h"                  # Root CA validity
default_x509_svid_ttl: "1h"    # Default workload certificate TTL
trust_domain: "research.example.org"
```

### Workload Attestation

```yaml
# k8s_sat (Kubernetes Service Account Token)
NodeAttestor "k8s_sat" {
    cluster = "kubernetes"
}

# k8s_psat (Projected Service Account Token)
WorkloadAttestor "k8s" {
    skip_kubelet_verification = true  # For local clusters
}
```

---

## Troubleshooting

### Common Issues

**Issue:** `Failed to fetch X509-SVID: connection refused`
```bash
# Solution: Verify SPIRE Agent is running
kubectl get pods -n spiffe-research | grep spire-agent
kubectl logs -n spiffe-research daemonset/spire-agent
```

**Issue:** `Certificate verification failed`
```bash
# Solution: Check SPIRE entries are registered
kubectl exec -n spiffe-research spire-server-0 -- \
  /opt/spire/bin/spire-server entry show
```

**Issue:** `LLM Gateway connection timeout`
```bash
# Solution: Verify gateway pod is running and has valid SPIFFE identity
kubectl get pods -n spiffe-research | grep lm-studio-gateway
kubectl logs -n spiffe-research deployment/lm-studio-gateway
```

### Verification Commands

```bash
# 1. Verify SPIRE infrastructure
kubectl get all -n spiffe-research

# 2. Check SPIFFE identities
kubectl exec -n spiffe-research spire-server-0 -- \
  /opt/spire/bin/spire-server entry show

# 3. Test mTLS connectivity
kubectl exec deployment/pipeline-orchestrator -n spiffe-research -- \
  curl -v https://threat-classifier:8443/health

# 4. Inspect certificate details
kubectl exec deployment/threat-classifier -n spiffe-research -- \
  python3 -c "from pyspiffe import WorkloadApiClient; \
              source = WorkloadApiClient().get_x509_source(); \
              print(source.svid)"
```

---

## Research Applications

This implementation supports research in:

1. **Zero-Trust Security**: Cryptographic workload identity without static credentials
2. **AI Agent Security**: Secure multi-agent communication in AI ecosystems
3. **Certificate Management**: Automated PKI for microservices
4. **mTLS Performance**: Overhead analysis in AI workloads
5. **Kubernetes Security**: SPIFFE/SPIRE integration patterns

### Extending the System

#### Adding New AI Agents

```python
# agents/new_agent_mtls.py
from pyspiffe import WorkloadApiClient
from flask import Flask, request
import ssl

app = Flask(__name__)

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    # Your AI logic here
    return {"result": "processed"}

if __name__ == '__main__':
    source = WorkloadApiClient().get_x509_source()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=source.svid.cert_chain_pem,
        keyfile=source.svid.private_key_pem
    )
    app.run(host='0.0.0.0', port=8447, ssl_context=context)
```

#### Integrating Alternative LLMs

```python
# lmstudio/llm_gateway.py (extend)
class LLMGateway:
    def __init__(self):
        self.providers = {
            'gemini': self._call_gemini,
            'openai': self._call_openai,      # Add OpenAI
            'anthropic': self._call_anthropic, # Add Anthropic
            'lmstudio': self._call_lmstudio
        }
    
    def _call_openai(self, prompt):
        # OpenAI integration
        pass
```

---

## Citation

If you use this work in your research, please cite:

```bibtex
@article{pappu2024spiffe,
  title={SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems},
  author={Pappu, Karthik and Bhushan, Badal and Mittal, Akshay},
  journal={IEEE Conference Proceedings},
  year={2024},
  url={https://github.com/karthikpappu/spiffe-ai-auth-test}
}
```

---

## References & Further Reading

### SPIFFE/SPIRE
- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/overview/) - Core identity standard
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/) - Reference implementation
- [py-spiffe Library](https://github.com/spiffe/py-spiffe) - Python SDK

### Zero-Trust Architecture
- NIST SP 800-207: Zero Trust Architecture
- Google BeyondCorp: Zero-trust security framework
- CNCF Security Whitepaper: Cloud-native security best practices

### AI Agent Security
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - LLM security risks
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) - AI governance

---

## License

This project is released for **research and educational purposes**.

**Copyright © 2024** Karthik Pappu, Badal Bhushan, Akshay Mittal

Permission is granted to use, modify, and distribute this software for non-commercial research purposes, provided that:
1. Proper attribution is given to the original authors
2. Any modifications are clearly documented
3. The IEEE paper is cited in derivative works

For commercial use, please contact the authors.

---

## Contact

- **Karthik Pappu**: [karthik.pappu@trojans.dsu.edu](mailto:karthik.pappu@trojans.dsu.edu)
- **Badal Bhushan**: [badalbhushan786@gmail.com](mailto:badalbhushan786@gmail.com)
- **Akshay Mittal**: [akshay.mittal@ieee.org](mailto:akshay.mittal@ieee.org)

**GitHub Repository**: [https://github.com/karthikpappu/spiffe-ai-auth-test](https://github.com/karthikpappu/spiffe-ai-auth-test)

---

## Acknowledgments

- **SPIFFE/SPIRE Community** for the robust identity framework
- **Google Gemini Team** for free-tier LLM access
- **Kubernetes Community** for cloud-native orchestration
- **Dakota State University**, **University of Cumberlands** for institutional support

---

*Last Updated: December 2024*
