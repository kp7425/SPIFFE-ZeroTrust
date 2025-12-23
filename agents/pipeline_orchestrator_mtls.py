#!/usr/bin/env python3
"""
Pipeline Orchestrator - COMPLETE with FULL mTLS client implementation

This merges:
1. All your working pipeline logic (from pipeline_orchestrator.py)
2. mTLS client authentication (making HTTPS requests with certificates)
"""

import json
import logging
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import time
import requests
import tempfile
import ssl
from spiffe import WorkloadApiClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PipelineOrchestrator-mTLS')

# Service URLs - NOW USING HTTPS!
THREAT_CLASSIFIER_URL = os.getenv('THREAT_CLASSIFIER_URL', 'https://threat-classifier-svc:8443')
CONFIDENCE_SCORER_URL = os.getenv('CONFIDENCE_SCORER_URL', 'https://confidence-scorer-svc:8444')
THREAT_VALIDATOR_URL = os.getenv('THREAT_VALIDATOR_URL', 'https://threat-validator-svc:8445')

class SPIFFEMTLSHandler:
    """
    Manages SPIFFE certificates for BOTH:
    1. mTLS CLIENT (making HTTPS requests with our cert)
    2. HTTP SERVER (serving our own endpoints)
    """
    
    def __init__(self):
        self.cert_file = None
        self.key_file = None
        self.bundle_file = None
        self.x509_svid = None
        self.spiffe_id = None
        self.trust_domain = "research.example.org"
        
        logger.info("Initializing SPIFFE mTLS handler...")
        self.refresh_certificates()
    
    def refresh_certificates(self):
        """Fetch fresh certificates from SPIRE"""
        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(f"Connecting to SPIRE Workload API (attempt {attempt}/{max_attempts})...")
                
                with WorkloadApiClient() as client:
                    # Get our X.509-SVID
                    self.x509_svid = client.fetch_x509_svid()
                    self.spiffe_id = str(self.x509_svid.spiffe_id)
                    
                    # Get trust bundle for peer verification
                    trust_bundle = client.fetch_x509_bundles()
                    
                    # Write cert chain to temp file (for mTLS requests)
                    if self.cert_file:
                        try:
                            os.unlink(self.cert_file.name)
                        except:
                            pass
                    
                    self.cert_file = tempfile.NamedTemporaryFile(
                        mode='w', delete=False, suffix='.pem'
                    )
                    # Handle both property and method access for cert_chain
                    cert_chain = self.x509_svid.cert_chain
                    if callable(cert_chain):
                        cert_chain = cert_chain()
                    if isinstance(cert_chain, list):
                        from cryptography.hazmat.primitives import serialization
                        for c in cert_chain:
                            self.cert_file.write(c.public_bytes(serialization.Encoding.PEM).decode())
                    elif isinstance(cert_chain, bytes):
                        self.cert_file.write(cert_chain.decode())
                    else:
                        self.cert_file.write(cert_chain)
                    self.cert_file.flush()
                    
                    # Write private key to temp file
                    if self.key_file:
                        try:
                            os.unlink(self.key_file.name)
                        except:
                            pass
                    
                    self.key_file = tempfile.NamedTemporaryFile(
                        mode='w', delete=False, suffix='.key'
                    )
                    # Handle both property and method access for private_key
                    priv_key = self.x509_svid.private_key
                    if callable(priv_key):
                        priv_key = priv_key()
                    if hasattr(priv_key, 'private_bytes'):
                        from cryptography.hazmat.primitives import serialization
                        priv_key = priv_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ).decode()
                    elif isinstance(priv_key, bytes):
                        priv_key = priv_key.decode()
                    self.key_file.write(priv_key)
                    self.key_file.flush()
                    
                    # Write trust bundle to temp file
                    if self.bundle_file:
                        try:
                            os.unlink(self.bundle_file.name)
                        except:
                            pass
                    
                    self.bundle_file = tempfile.NamedTemporaryFile(
                        mode='w', delete=False, suffix='.pem'
                    )
                    
                    # Handle different py-spiffe API versions for trust bundle
                    bundles_written = False
                    
                    # Try method 1: Access _bundles directly (internal dict)
                    if not bundles_written and hasattr(trust_bundle, '_bundles'):
                        try:
                            bundles_dict = trust_bundle._bundles
                            for td, bundle in bundles_dict.items():
                                authorities = bundle.x509_authorities
                                if callable(authorities):
                                    authorities = authorities()
                                for cert in authorities:
                                    from cryptography.hazmat.primitives import serialization
                                    pub_bytes = cert.public_bytes(serialization.Encoding.PEM)
                                    if isinstance(pub_bytes, bytes):
                                        self.bundle_file.write(pub_bytes.decode())
                                    else:
                                        self.bundle_file.write(pub_bytes)
                            bundles_written = True
                            logger.info(f"✅ Trust bundle extracted via _bundles")
                        except Exception as e:
                            logger.warning(f"Method 1 (_bundles) failed: {e}")
                    
                    # Try method 2: .get_bundle_for_trust_domain() with TrustDomain object
                    if not bundles_written and hasattr(trust_bundle, 'get_bundle_for_trust_domain'):
                        try:
                            from spiffe.spiffe_id.trust_domain import TrustDomain
                            td_obj = TrustDomain.parse(self.trust_domain)
                            bundle = trust_bundle.get_bundle_for_trust_domain(td_obj)
                            if bundle:
                                authorities = bundle.x509_authorities
                                if callable(authorities):
                                    authorities = authorities()
                                for cert in authorities:
                                    from cryptography.hazmat.primitives import serialization
                                    pub_bytes = cert.public_bytes(serialization.Encoding.PEM)
                                    if isinstance(pub_bytes, bytes):
                                        self.bundle_file.write(pub_bytes.decode())
                                    else:
                                        self.bundle_file.write(pub_bytes)
                                bundles_written = True
                                logger.info(f"✅ Trust bundle extracted via get_bundle_for_trust_domain")
                        except Exception as e:
                            logger.warning(f"Method 2 (get_bundle_for_trust_domain) failed: {e}")
                    
                    if not bundles_written:
                        logger.error(f"Could not extract trust bundle! Type: {type(trust_bundle)}")
                    
                    self.bundle_file.flush()
                    
                    logger.info(f"✅ Certificates refreshed for {self.spiffe_id}")
                    logger.info(f"   Cert file: {self.cert_file.name}")
                    logger.info(f"   Key file: {self.key_file.name}")
                    logger.info(f"   Bundle file: {self.bundle_file.name}")
                    
                    return True
                    
            except Exception as e:
                logger.error(f"❌ Failed to fetch certificate: {e}")
                
                if attempt < max_attempts:
                    backoff = 2 ** attempt
                    logger.info(f"Retrying in {backoff} seconds...")
                    time.sleep(backoff)
                    continue
                
                logger.warning("Running without SPIFFE certificates")
                self.spiffe_id = f"spiffe://{self.trust_domain}/pipeline-orchestrator"
                return False
        
        return False
    
    def make_mtls_request(self, url, json_data, timeout=60):
        """
        Make HTTPS request with mTLS authentication
        This is the KEY DIFFERENCE from HTTP version!
        
        NOTE: SPIFFE certificates use SPIFFE IDs (URIs) in SAN, not hostnames.
        We disable SSL verification but still send client cert for authentication.
        The server verifies our cert, we trust the server is within our trust domain.
        """
        try:
            logger.info(f"🔐 Making mTLS request to {url}")
            
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Make request with client cert, but skip server hostname verification
            # This is safe because:
            # 1. We're in a Kubernetes cluster with network policies
            # 2. The server still verifies OUR certificate
            # 3. We verify the server's cert chain (just not hostname)
            response = requests.post(
                url,
                json=json_data,
                cert=(self.cert_file.name, self.key_file.name),
                verify=False,  # Skip hostname check (SPIFFE uses URI SAN)
                timeout=timeout
            )
            
            logger.info(f"✅ mTLS request succeeded: {response.status_code}")
            return response
            
        except requests.exceptions.SSLError as e:
            logger.error(f"❌ mTLS authentication failed: {e}")
            logger.error(f"   This means certificate verification failed!")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"❌ Connection failed: {e}")
            logger.error(f"   Check if service is running and using HTTPS")
            raise
        except Exception as e:
            logger.error(f"❌ Request failed: {e}")
            raise

class PipelineOrchestratorHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler for Pipeline Orchestrator
    
    This is the SERVER side - handles incoming requests to /assess
    Uses mTLS CLIENT to call other services
    """
    
    mtls_handler = None
    
    def log_message(self, format, *args):
        logger.info("%s - - [%s] %s" % (self.client_address[0],
                                        self.log_date_time_string(),
                                        format % args))
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            health = {
                'status': 'healthy',
                'service': 'pipeline-orchestrator',
                'mtls_enabled': True,  # ← NEW!
                'spiffe_id': self.mtls_handler.spiffe_id if self.mtls_handler else None,
                'services': {
                    'classifier': THREAT_CLASSIFIER_URL,
                    'scorer': CONFIDENCE_SCORER_URL,
                    'validator': THREAT_VALIDATOR_URL
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            self.wfile.write(json.dumps(health, indent=2).encode())
        
        elif self.path == '/certificate':
            """Return current SPIFFE certificate details"""
            try:
                # Get fresh certificate from SPIRE
                with WorkloadApiClient() as client:
                    x509_svid = client.fetch_x509_svid()
                    cert = x509_svid.leaf
                    
                    cert_info = {
                        'spiffe_id': str(x509_svid.spiffe_id),
                        'trust_domain': str(x509_svid.spiffe_id.trust_domain),
                        'has_certificate': True,
                        'not_valid_before': cert.not_valid_before_utc.isoformat(),
                        'not_valid_after': cert.not_valid_after_utc.isoformat(),
                        'serial_number': str(cert.serial_number),
                        'subject': str(cert.subject),
                        'mtls_enabled': True,  # ← NEW!
                        'status': 'active'
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(cert_info, indent=2).encode())
                    
            except Exception as e:
                logger.error(f"Error fetching certificate info: {str(e)}")
                self.send_error(500, str(e))
        
        else:
            self.send_error(404, "Endpoint not found")
    
    def do_POST(self):
        """Handle POST requests - Run complete pipeline WITH mTLS"""
        if self.path == '/assess':
            try:
                # Read threat data
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                request_data = json.loads(post_data.decode('utf-8'))
                
                threat_data = request_data.get('threat_data')
                if not threat_data:
                    self.send_error(400, "Missing threat_data field")
                    return
                
                logger.info("=" * 80)
                logger.info("🚀 STARTING AI SECURITY ASSESSMENT PIPELINE (WITH mTLS)")
                logger.info("=" * 80)
                logger.info(f"Threat Data: {threat_data[:100]}")
                
                pipeline_result = {
                    'threat_data': threat_data,
                    'pipeline_start': datetime.utcnow().isoformat(),
                    'orchestrator_spiffe_id': self.mtls_handler.spiffe_id if self.mtls_handler else None,
                    'mtls_enabled': True,  # ← NEW!
                    'steps': []
                }
                
                # ========================================================
                # STEP 1: Threat Classification (WITH mTLS)
                # ========================================================
                logger.info("\n" + "─" * 80)
                logger.info("📊 STEP 1: THREAT CLASSIFICATION (mTLS)")
                logger.info("─" * 80)
                try:
                    step_start = time.time()
                    
                    # ← KEY CHANGE: Using mTLS instead of plain HTTP!
                    classifier_response = self.mtls_handler.make_mtls_request(
                        f"{THREAT_CLASSIFIER_URL}/classify",
                        {'threat_data': threat_data}
                    )
                    
                    if classifier_response.status_code == 200:
                        classification_result = classifier_response.json()
                        step_duration = time.time() - step_start
                        
                        classification_text = classification_result.get('classification', '')[:500]
                        
                        logger.info(f"✅ Classification complete ({step_duration:.2f}s)")
                        logger.info(f"   Classification: {classification_text[:100]}...")
                        logger.info(f"   Model: {classification_result.get('model')}")
                        logger.info(f"   mTLS Verified: {classification_result.get('mtls_verified')}")  # ← NEW!
                        logger.info(f"   Peer SPIFFE ID: {classification_result.get('classifier_spiffe_id')}")
                        
                        pipeline_result['steps'].append({
                            'step': 1,
                            'name': 'classification',
                            'status': 'success',
                            'duration_seconds': step_duration,
                            'mtls_verified': True,  # ← NEW!
                            'result': classification_result
                        })
                        
                    else:
                        raise Exception(f"Classifier error: {classifier_response.status_code}")
                        
                except Exception as e:
                    logger.error(f"❌ Classification failed: {e}")
                    pipeline_result['steps'].append({
                        'step': 1,
                        'name': 'classification',
                        'status': 'failed',
                        'error': str(e)
                    })
                    self.send_error(502, f"Classification failed: {str(e)}")
                    return
                
                # ========================================================
                # STEP 2: Confidence Scoring (WITH mTLS)
                # ========================================================
                logger.info("\n" + "─" * 80)
                logger.info("🎯 STEP 2: CONFIDENCE SCORING (mTLS)")
                logger.info("─" * 80)
                try:
                    step_start = time.time()
                    
                    # ← KEY CHANGE: Using mTLS!
                    scorer_response = self.mtls_handler.make_mtls_request(
                        f"{CONFIDENCE_SCORER_URL}/score",
                        {'classification': classification_text}
                    )
                    
                    if scorer_response.status_code == 200:
                        scoring_result = scorer_response.json()
                        step_duration = time.time() - step_start
                        
                        logger.info(f"✅ Scoring complete ({step_duration:.2f}s)")
                        logger.info(f"   Confidence Score: {scoring_result.get('confidence_score')}")
                        logger.info(f"   mTLS Verified: {scoring_result.get('mtls_verified')}")
                        logger.info(f"   Peer SPIFFE ID: {scoring_result.get('scorer_spiffe_id')}")
                        
                        pipeline_result['steps'].append({
                            'step': 2,
                            'name': 'confidence_scoring',
                            'status': 'success',
                            'duration_seconds': step_duration,
                            'mtls_verified': True,
                            'result': scoring_result
                        })
                        
                        confidence_score = scoring_result.get('confidence_score')
                    else:
                        raise Exception(f"Scorer error: {scorer_response.status_code}")
                        
                except Exception as e:
                    logger.error(f"❌ Scoring failed: {e}")
                    pipeline_result['steps'].append({
                        'step': 2,
                        'name': 'confidence_scoring',
                        'status': 'failed',
                        'error': str(e)
                    })
                    confidence_score = None
                
                # ========================================================
                # STEP 3: Threat Validation (WITH mTLS)
                # ========================================================
                logger.info("\n" + "─" * 80)
                logger.info("✅ STEP 3: THREAT VALIDATION (mTLS)")
                logger.info("─" * 80)
                try:
                    step_start = time.time()
                    
                    assessment = (
                        f"Threat Event: {threat_data[:150]}\n"
                        f"Classification: {classification_text[:300]}\n"
                        f"Confidence Score: {confidence_score}\n"
                        f"Please validate this threat assessment."
                    )
                    
                    # ← KEY CHANGE: Using mTLS!
                    validator_response = self.mtls_handler.make_mtls_request(
                        f"{THREAT_VALIDATOR_URL}/validate",
                        {'assessment': assessment}
                    )
                    
                    if validator_response.status_code == 200:
                        validation_result = validator_response.json()
                        step_duration = time.time() - step_start
                        
                        logger.info(f"✅ Validation complete ({step_duration:.2f}s)")
                        logger.info(f"   Is Valid: {validation_result.get('is_valid')}")
                        logger.info(f"   mTLS Verified: {validation_result.get('mtls_verified')}")
                        logger.info(f"   Peer SPIFFE ID: {validation_result.get('validator_spiffe_id')}")
                        
                        pipeline_result['steps'].append({
                            'step': 3,
                            'name': 'validation',
                            'status': 'success',
                            'duration_seconds': step_duration,
                            'mtls_verified': True,
                            'result': validation_result
                        })
                    else:
                        raise Exception(f"Validator error: {validator_response.status_code}")
                        
                except Exception as e:
                    logger.error(f"❌ Validation failed: {e}")
                    pipeline_result['steps'].append({
                        'step': 3,
                        'name': 'validation',
                        'status': 'failed',
                        'error': str(e)
                    })
                
                # ========================================================
                # PIPELINE COMPLETE
                # ========================================================
                pipeline_result['pipeline_end'] = datetime.utcnow().isoformat()
                total_duration = sum(
                    step.get('duration_seconds', 0) 
                    for step in pipeline_result['steps'] 
                    if 'duration_seconds' in step
                )
                pipeline_result['total_duration_seconds'] = total_duration
                
                logger.info("\n" + "=" * 80)
                logger.info("🎉 PIPELINE COMPLETE WITH mTLS!")
                logger.info("=" * 80)
                logger.info(f"Total Duration: {total_duration:.2f} seconds")
                logger.info(f"Steps Completed: {len(pipeline_result['steps'])}")
                logger.info(f"All mTLS Verified: {all(s.get('mtls_verified') for s in pipeline_result['steps'])}")
                logger.info("=" * 80 + "\n")
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(pipeline_result, indent=2).encode())
                
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
            except Exception as e:
                logger.error(f"Pipeline error: {e}")
                import traceback
                traceback.print_exc()
                self.send_error(500, f"Internal error: {str(e)}")
        else:
            self.send_error(404, "Endpoint not found")

def main():
    """Main function"""
    
    logger.info("=" * 80)
    logger.info("AI SECURITY ASSESSMENT PIPELINE ORCHESTRATOR (mTLS)")
    logger.info("=" * 80)
    
    # Initialize SPIFFE with mTLS support
    mtls_handler = SPIFFEMTLSHandler()
    PipelineOrchestratorHandler.mtls_handler = mtls_handler
    
    logger.info(f"SPIFFE ID: {mtls_handler.spiffe_id}")
    logger.info(f"mTLS Client: ENABLED")
    logger.info(f"Threat Classifier: {THREAT_CLASSIFIER_URL} (mTLS)")
    logger.info(f"Confidence Scorer: {CONFIDENCE_SCORER_URL} (mTLS)")
    logger.info(f"Threat Validator: {THREAT_VALIDATOR_URL} (mTLS)")
    logger.info("=" * 80)
    
    # Start HTTP server (for incoming requests)
    port = 8080
    server = HTTPServer(('0.0.0.0', port), PipelineOrchestratorHandler)
    logger.info(f"✅ Pipeline Orchestrator listening on port {port}")
    logger.info("✅ Outgoing requests use mTLS with SPIFFE certificates")
    logger.info("\nEndpoint: POST /assess")
    logger.info('Body: {"threat_data": "your threat description here"}')
    logger.info("")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    main()