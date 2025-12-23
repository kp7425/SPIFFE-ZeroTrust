# Contributing to SPIFFE-Based Zero-Trust Authentication for AI Agents

We welcome contributions from the research community! This project supports academic research in zero-trust security, AI agent authentication, and SPIFFE/SPIRE implementations.

## How to Contribute

### Reporting Issues

If you encounter bugs or have feature requests:

1. **Search existing issues** to avoid duplicates
2. **Create a new issue** with:
   - Clear description of the problem
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - System environment (Kubernetes version, OS, etc.)
   - Relevant logs or error messages

### Submitting Changes

1. **Fork the repository**
   ```bash
   git clone https://github.com/karthikpappu/spiffe-ai-auth-test.git
   cd spiffe-ai-auth-test
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow existing code style (PEP 8 for Python)
   - Add comments explaining complex logic
   - Update documentation if needed

3. **Test your changes**
   ```bash
   # Deploy your modified system
   ./scripts/deploy-spire.sh
   kubectl apply -f configs/
   
   # Run tests
   kubectl exec deployment/pipeline-orchestrator -n spiffe-research -- \
     curl http://localhost:8080/assess -X POST \
     -H "Content-Type: application/json" \
     -d '{"threat_data":"test"}'
   ```

4. **Submit a pull request**
   - Provide clear description of changes
   - Reference related issues
   - Include test results

### Areas for Contribution

#### 1. Performance Optimization
- Reduce mTLS handshake overhead
- Optimize certificate caching
- Improve LLM gateway response times

#### 2. Security Enhancements
- Implement shorter certificate TTLs (2-minute rotation)
- Add streaming SVID updates using `X509Source.watch()`
- Enhance audit logging

#### 3. Feature Additions
- Support for additional LLM providers (OpenAI, Anthropic, local models)
- New AI agents for different security tasks
- Multi-cluster SPIFFE federation

#### 4. Documentation
- Additional deployment guides (AWS EKS, Azure AKS, GKE)
- Troubleshooting scenarios
- Performance benchmarking scripts

#### 5. Research Extensions
- Integration with SIEM systems
- Real-time threat intelligence feeds
- Machine learning model security

### Code Style Guidelines

**Python:**
```python
# Use type hints
def classify_threat(threat_data: str) -> dict:
    """Classify threat severity.
    
    Args:
        threat_data: Raw threat information
        
    Returns:
        Classification result with severity and reasoning
    """
    pass

# Use descriptive variable names
svid_bundle = source.get_x509_bundle()  # Good
x = source.get_x509_bundle()           # Bad

# Add logging
import logging
logger = logging.getLogger(__name__)
logger.info(f"Processing threat: {threat_id}")
```

**Kubernetes YAML:**
```yaml
# Use consistent indentation (2 spaces)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-classifier
  labels:
    app: threat-classifier
    version: "1.0"
```

### Research Collaboration

If you're using this work in your research:

1. **Cite the paper** (see [CITATION.cff](CITATION.cff))
2. **Share your findings** - We'd love to hear about your research
3. **Contribute improvements** back to the community
4. **Collaborate** - Contact us for joint research opportunities

### Academic Ethics

- Maintain academic integrity in all contributions
- Properly attribute external code or algorithms
- Document experimental methodologies
- Share negative results (what didn't work and why)

## Contact

- **Karthik Pappu**: karthik.pappu@trojans.dsu.edu
- **Badal Bhushan**: badalbhushan786@gmail.com
- **Akshay Mittal**: akshay.mittal@ieee.org

## License

All contributions will be licensed under the same terms as the project (see [LICENSE](LICENSE)).
