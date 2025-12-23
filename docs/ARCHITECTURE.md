# Architecture Overview

## System Components

### 1. SPIRE Infrastructure

**SPIRE Server** (Certificate Authority)
- Manages workload identities
- Issues X.509-SVID certificates
- Enforces registration policies
- 1-hour certificate TTL

**SPIRE Agent** (DaemonSet)
- Runs on every Kubernetes node
- Attests workload identity
- Delivers certificates to workloads
- Handles automatic rotation

### 2. AI Agent Microservices

**Pipeline Orchestrator**
- Central coordination service
- Receives analysis requests
- Orchestrates multi-agent workflow
- SPIFFE ID: `spiffe://k8s.local/ns/default/sa/pipeline-orchestrator`

**Threat Classifier**
- Analyzes security threats
- Uses LLM for classification
- Returns threat categories
- SPIFFE ID: `spiffe://k8s.local/ns/default/sa/threat-classifier`

**Threat Validator**
- Validates classification results
- Cross-references threat intelligence
- Confidence scoring
- SPIFFE ID: `spiffe://k8s.local/ns/default/sa/threat-validator`

**Confidence Scorer**
- Calculates final confidence scores
- Aggregates multi-agent results
- Risk assessment
- SPIFFE ID: `spiffe://k8s.local/ns/default/sa/confidence-scorer`

### 3. LLM Gateway

**Function**: Secure proxy for Google Gemini API
- Receives mTLS requests from agents
- Verifies SVID certificates
- Forwards to Gemini 2.0 Flash
- Returns structured responses

**SPIFFE ID**: `spiffe://k8s.local/ns/default/sa/llm-gateway`

## Authentication Flow

```
1. Agent starts → Requests SVID from SPIRE Agent
                          ↓
2. SPIRE Agent attests workload identity (K8s SA)
                          ↓
3. SPIRE Server issues X.509-SVID certificate (1h TTL)
                          ↓
4. Agent uses SVID for mTLS connections
                          ↓
5. SPIRE automatically rotates certificate before expiry
```

## Communication Matrix

| Source              | Destination         | Protocol | Authentication |
|---------------------|---------------------|----------|----------------|
| Orchestrator        | Classifier          | HTTPS    | mTLS (SVID)    |
| Orchestrator        | Validator           | HTTPS    | mTLS (SVID)    |
| Orchestrator        | Scorer              | HTTPS    | mTLS (SVID)    |
| Classifier          | LLM Gateway         | HTTPS    | mTLS (SVID)    |
| Validator           | LLM Gateway         | HTTPS    | mTLS (SVID)    |
| Scorer              | LLM Gateway         | HTTPS    | mTLS (SVID)    |
| LLM Gateway         | Gemini API          | HTTPS    | API Key        |

## Certificate Lifecycle

```
0:00 ────────────────────────────────► 1:00
 │                                       │
 │   Certificate Valid Period           │
 │                                       │
 └──► Auto-rotation starts at 0:45 ─────┘
                                         │
                                         └──► New cert issued
                                              Old cert revoked
```

**Key Parameters**:
- Certificate TTL: 1 hour
- Rotation window: Last 15 minutes
- Grace period: 5 minutes overlap
- Attestation: Kubernetes Service Account

## Security Properties

1. **Zero Static Secrets**: No hardcoded credentials
2. **Short-lived Credentials**: 1-hour maximum validity
3. **Automatic Rotation**: No manual intervention required
4. **Cryptographic Identity**: X.509 certificates with private keys
5. **Mutual Authentication**: Both parties verify each other
6. **Audit Trail**: All authentications logged with SPIFFE IDs

## Scalability

- **Horizontal**: Add more agent replicas
- **Vertical**: Increase SPIRE server resources
- **Multi-cluster**: SPIRE federation support
- **Multi-cloud**: SPIFFE IDs portable across providers

## Failure Modes

| Failure                | Impact              | Mitigation           |
|------------------------|---------------------|----------------------|
| SPIRE Server down      | No new certificates | HA deployment        |
| Certificate expired    | Auth fails          | Auto-rotation        |
| SPIRE Agent down       | Node workloads fail | DaemonSet recovery   |
| Gateway unavailable    | LLM access blocked  | Retry logic          |
| Gemini API error       | Analysis fails      | Fallback responses   |

## Performance Characteristics

- **Certificate issuance**: <100ms
- **mTLS handshake overhead**: ~50ms
- **Certificate rotation**: Transparent (no downtime)
- **SPIRE server capacity**: 10,000+ workloads
- **Agent memory**: ~50MB per pod
