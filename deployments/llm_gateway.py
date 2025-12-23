#!/usr/bin/env python3
"""
LLM Gateway - Multi-Provider mTLS Implementation

Supports multiple LLM backends:
1. LM Studio (local) - default
2. Google Gemini (cloud) - requires GEMINI_API_KEY

Switch backends via LLM_BACKEND environment variable:
- LLM_BACKEND=lmstudio (default)
- LLM_BACKEND=gemini

All inter-agent communication uses mTLS with SPIFFE certificates.
The API key (if used) is isolated to this gateway only.
"""

import os
import logging
import ssl
import sys
import tempfile
import time
import socket
import threading
import re
from http.server import HTTPServer
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server
from flask import Flask, request, jsonify
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Install dependencies
try:
    from spiffe import WorkloadApiClient
except ImportError:
    print("Installing dependencies...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "spiffe", "cryptography", "flask", "google-generativeai", "--break-system-packages"])
    from spiffe import WorkloadApiClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('LLMGateway-mTLS')

app = Flask(__name__)

# =============================================================================
# LLM BACKEND CONFIGURATION
# =============================================================================

# Backend selection: 'gemini' (default) or 'lmstudio'
LLM_BACKEND = os.getenv('LLM_BACKEND', 'gemini').lower()

# LM Studio configuration (local)
LM_STUDIO_HOST = os.getenv('LM_STUDIO_HOST', 'host.docker.internal')
LM_STUDIO_PORT = os.getenv('LM_STUDIO_PORT', '1234')
LM_STUDIO_URL = f"http://{LM_STUDIO_HOST}:{LM_STUDIO_PORT}/v1/chat/completions"
LM_MODEL = os.getenv('LM_MODEL', 'qwen/qwen3-4b-2507')

# Gemini configuration (cloud)
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash')
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Global mTLS handler
mtls_handler = None

# Thread-local storage for peer certificate
_peer_cert_local = threading.local()

# =============================================================================
# LLM BACKEND FUNCTIONS
# =============================================================================

def call_lmstudio(messages, temperature=0.3, max_tokens=500):
    """Call LM Studio local API"""
    logger.info(f"🤖 Calling LM Studio: {LM_STUDIO_URL}")
    
    response = requests.post(
        LM_STUDIO_URL,
        json={
            "model": LM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        },
        timeout=60
    )
    
    if response.status_code != 200:
        raise Exception(f"LM Studio error: {response.status_code} - {response.text}")
    
    result = response.json()
    return {
        "content": result['choices'][0]['message']['content'],
        "model": LM_MODEL,
        "backend": "lmstudio",
        "tokens_used": result.get('usage', {})
    }


def call_gemini(messages, temperature=0.3, max_tokens=500):
    """Call Google Gemini API via HTTPS"""
    if not GEMINI_API_KEY:
        raise Exception("GEMINI_API_KEY not set")
    
    logger.info(f"🤖 Calling Gemini API: {GEMINI_MODEL}")
    
    # Convert OpenAI-style messages to Gemini format
    # Gemini uses 'parts' with 'text' instead of 'content'
    contents = []
    system_instruction = None
    
    for msg in messages:
        role = msg['role']
        content = msg['content']
        
        if role == 'system':
            # Gemini handles system prompts differently
            system_instruction = content
        elif role == 'user':
            contents.append({
                "role": "user",
                "parts": [{"text": content}]
            })
        elif role == 'assistant':
            contents.append({
                "role": "model",
                "parts": [{"text": content}]
            })
    
    # Build request payload
    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens
        }
    }
    
    # Add system instruction if present
    if system_instruction:
        payload["systemInstruction"] = {
            "parts": [{"text": system_instruction}]
        }
    
    # Call Gemini API (HTTPS with API key)
    response = requests.post(
        f"{GEMINI_URL}?key={GEMINI_API_KEY}",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=60
    )
    
    if response.status_code != 200:
        error_detail = response.text
        try:
            error_json = response.json()
            if 'error' in error_json:
                error_detail = error_json['error'].get('message', response.text)
        except:
            pass
        raise Exception(f"Gemini API error: {response.status_code} - {error_detail}")
    
    result = response.json()
    
    # Extract response text from Gemini format
    try:
        content = result['candidates'][0]['content']['parts'][0]['text']
    except (KeyError, IndexError):
        raise Exception(f"Unexpected Gemini response format: {result}")
    
    # Get token usage if available
    tokens_used = {}
    if 'usageMetadata' in result:
        tokens_used = {
            'prompt_tokens': result['usageMetadata'].get('promptTokenCount', 0),
            'completion_tokens': result['usageMetadata'].get('candidatesTokenCount', 0),
            'total_tokens': result['usageMetadata'].get('totalTokenCount', 0)
        }
    
    return {
        "content": content,
        "model": GEMINI_MODEL,
        "backend": "gemini",
        "tokens_used": tokens_used
    }


def call_llm(messages, temperature=0.3, max_tokens=500):
    """
    Call the configured LLM backend
    
    This is the single point where backend selection happens.
    All endpoints use this function.
    """
    if LLM_BACKEND == 'gemini':
        return call_gemini(messages, temperature, max_tokens)
    else:
        return call_lmstudio(messages, temperature, max_tokens)


# =============================================================================
# SSL/TLS WSGI SERVER FOR mTLS
# =============================================================================

class SSLWSGIRequestHandler(WSGIRequestHandler):
    """Custom WSGI request handler that captures SSL peer certificate"""
    
    def get_environ(self):
        environ = super().get_environ()
        if hasattr(self.request, 'getpeercert'):
            peer_cert = self.request.getpeercert()
            if peer_cert:
                environ['peercert'] = peer_cert
                _peer_cert_local.cert = peer_cert
        return environ
    
    def log_message(self, format, *args):
        logger.info("%s - - %s" % (self.address_string(), format % args))


class SSLWSGIServer(WSGIServer):
    """WSGI Server with SSL/TLS support for mTLS"""
    
    def __init__(self, server_address, RequestHandlerClass, ssl_context):
        super().__init__(server_address, RequestHandlerClass)
        self.ssl_context = ssl_context
    
    def get_request(self):
        sock, addr = self.socket.accept()
        ssl_sock = self.ssl_context.wrap_socket(sock, server_side=True)
        return ssl_sock, addr


# =============================================================================
# SPIFFE mTLS HANDLER
# =============================================================================

class SPIFFEMTLSHandler:
    """Manages SPIFFE certificates for mTLS server"""
    
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
        """Fetch X.509-SVID certificate from SPIRE Agent"""
        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(f"Connecting to SPIRE Workload API (attempt {attempt}/{max_attempts})...")
                
                with WorkloadApiClient() as client:
                    self.x509_svid = client.fetch_x509_svid()
                    self.spiffe_id = str(self.x509_svid.spiffe_id)
                    trust_bundle = client.fetch_x509_bundles()
                    
                    logger.info("✅ Successfully fetched X.509-SVID certificate")
                    logger.info(f"✅ SPIFFE ID: {self.spiffe_id}")
                    
                    cert = self.x509_svid.leaf
                    logger.info(f"✅ Certificate serial: {cert.serial_number}")
                    logger.info(f"✅ Valid until: {cert.not_valid_after_utc.isoformat()}")
                    
                    # Clean up old temp files
                    for f in [self.cert_file, self.key_file, self.bundle_file]:
                        if f:
                            try:
                                os.unlink(f.name)
                            except:
                                pass
                    
                    # Write certificate chain
                    self.cert_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
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
                    
                    # Write private key
                    self.key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key')
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
                    
                    # Write trust bundle
                    self.bundle_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                    bundles_written = False
                    
                    if hasattr(trust_bundle, '_bundles'):
                        try:
                            for td, bundle in trust_bundle._bundles.items():
                                authorities = bundle.x509_authorities
                                if callable(authorities):
                                    authorities = authorities()
                                for cert in authorities:
                                    from cryptography.hazmat.primitives import serialization
                                    pub_bytes = cert.public_bytes(serialization.Encoding.PEM)
                                    self.bundle_file.write(pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes)
                            bundles_written = True
                        except Exception as e:
                            logger.warning(f"Trust bundle method 1 failed: {e}")
                    
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
                                    self.bundle_file.write(pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes)
                                bundles_written = True
                        except Exception as e:
                            logger.warning(f"Trust bundle method 2 failed: {e}")
                    
                    self.bundle_file.flush()
                    logger.info(f"✅ Trust bundle written")
                    
                    return True
                    
            except Exception as e:
                logger.error(f"❌ Failed to fetch certificate: {e}")
                if attempt < max_attempts:
                    time.sleep(2 ** attempt)
                    continue
                return False
        
        return False
    
    def create_ssl_context(self):
        """Create SSL context for mTLS"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file.name, keyfile=self.key_file.name)
        context.load_verify_locations(cafile=self.bundle_file.name)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        logger.info("✅ SSL context created with mTLS enabled")
        return context
    
    def get_certificate_info(self):
        """Get current certificate information"""
        if self.x509_svid:
            cert = self.x509_svid.leaf
            return {
                'spiffe_id': self.spiffe_id,
                'trust_domain': self.trust_domain,
                'has_certificate': True,
                'mtls_enabled': True,
                'not_valid_before': cert.not_valid_before_utc.isoformat(),
                'not_valid_after': cert.not_valid_after_utc.isoformat(),
                'serial_number': str(cert.serial_number),
                'llm_backend': LLM_BACKEND,
                'status': 'active'
            }
        return {'status': 'no certificate'}


# =============================================================================
# AUTHENTICATION & AUTHORIZATION
# =============================================================================

def extract_peer_spiffe_id():
    """Extract SPIFFE ID from peer's certificate"""
    try:
        peer_cert = request.environ.get('peercert') or getattr(_peer_cert_local, 'cert', None)
        
        if not peer_cert:
            logger.error("❌ No client certificate in request!")
            return None
        
        san = peer_cert.get('subjectAltName', [])
        spiffe_ids = [uri for typ, uri in san if typ == 'URI' and uri.startswith('spiffe://')]
        
        if not spiffe_ids:
            logger.error("❌ No SPIFFE ID in certificate SAN!")
            return None
        
        spiffe_id = spiffe_ids[0]
        logger.info(f"✅ Extracted peer SPIFFE ID: {spiffe_id}")
        return spiffe_id
        
    except Exception as e:
        logger.error(f"❌ Failed to extract SPIFFE ID: {e}")
        return None


def authorize_peer(peer_spiffe_id):
    """Authorize peer based on SPIFFE ID"""
    allowed_callers = [
        'spiffe://research.example.org/threat-classifier',
        'spiffe://research.example.org/confidence-scorer',
        'spiffe://research.example.org/threat-validator',
    ]
    
    if peer_spiffe_id in allowed_callers:
        logger.info(f"✅ Authorized caller: {peer_spiffe_id}")
        return True
    
    logger.error(f"❌ UNAUTHORIZED caller: {peer_spiffe_id}")
    return False


# =============================================================================
# FLASK ENDPOINTS
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint (no auth required)"""
    backend_status = "unknown"
    
    if LLM_BACKEND == 'gemini':
        backend_status = "configured" if GEMINI_API_KEY else "no API key"
    else:
        try:
            resp = requests.get(f"http://{LM_STUDIO_HOST}:{LM_STUDIO_PORT}/v1/models", timeout=2)
            backend_status = "available" if resp.status_code == 200 else "unavailable"
        except:
            backend_status = "unavailable"
    
    return jsonify({
        "status": "healthy",
        "service": "llm-gateway",
        "mtls_enabled": True,
        "spiffe_id": mtls_handler.spiffe_id if mtls_handler else None,
        "llm_backend": LLM_BACKEND,
        "llm_model": GEMINI_MODEL if LLM_BACKEND == 'gemini' else LM_MODEL,
        "backend_status": backend_status
    })


@app.route('/certificate', methods=['GET'])
def get_certificate():
    """Return current SPIFFE certificate details"""
    if not mtls_handler:
        return jsonify({'error': 'mTLS handler not initialized'}), 503
    return jsonify(mtls_handler.get_certificate_info())


@app.route('/classify', methods=['POST'])
def classify_threat():
    """Classify security threats using LLM"""
    peer_spiffe_id = extract_peer_spiffe_id()
    if not peer_spiffe_id:
        return jsonify({"error": "Authentication failed"}), 403
    if not authorize_peer(peer_spiffe_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    threat_data = request.json.get('threat_data', '')
    if not threat_data:
        return jsonify({"error": "No threat_data provided"}), 400
    
    logger.info(f"📥 Classification request from: {peer_spiffe_id}")
    
    system_prompt = """You are a security threat classifier. Analyze the given security event and classify it as:
- HIGH: Critical threats requiring immediate action
- MEDIUM: Moderate threats needing investigation
- LOW: Minor issues or false positives

Provide your classification and brief reasoning."""
    
    try:
        result = call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Classify this security event: {threat_data}"}
        ], temperature=0.3, max_tokens=500)
        
        logger.info(f"✅ Classification complete via {result['backend']}")
        
        return jsonify({
            "classification": result['content'],
            "model": result['model'],
            "backend": result['backend'],
            "authenticated_via": peer_spiffe_id,
            "mtls_verified": True,
            "gateway": "llm-gateway",
            "tokens_used": result['tokens_used']
        })
        
    except requests.exceptions.Timeout:
        return jsonify({"error": "LLM request timed out"}), 504
    except requests.exceptions.ConnectionError as e:
        return jsonify({"error": f"LLM unavailable: {str(e)}"}), 503
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/score', methods=['POST'])
def score_confidence():
    """Score confidence levels using LLM"""
    peer_spiffe_id = extract_peer_spiffe_id()
    if not peer_spiffe_id:
        return jsonify({"error": "Authentication failed"}), 403
    if not authorize_peer(peer_spiffe_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    classification_data = request.json.get('classification', '')
    if not classification_data:
        return jsonify({"error": "No classification provided"}), 400
    
    logger.info(f"📥 Confidence scoring request from: {peer_spiffe_id}")
    
    system_prompt = """You are a confidence scorer. Given a security threat classification, 
provide a confidence score between 0.0 and 1.0, where:
- 1.0 = Extremely confident, clear indicators
- 0.5 = Moderate confidence, some uncertainty
- 0.0 = Very uncertain, insufficient data

Respond with ONLY the numeric score (e.g., 0.85)."""
    
    try:
        result = call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Score confidence for: {classification_data}"}
        ], temperature=0.2, max_tokens=100)
        
        score_text = result['content'].strip()
        
        # Extract numeric score
        try:
            score_match = re.search(r'0?\.\d+|1\.0+', score_text)
            confidence_score = float(score_match.group()) if score_match else 0.5
            confidence_score = max(0.0, min(1.0, confidence_score))
        except:
            confidence_score = 0.5
        
        logger.info(f"✅ Confidence score: {confidence_score} via {result['backend']}")
        
        return jsonify({
            "confidence_score": confidence_score,
            "raw_response": score_text,
            "model": result['model'],
            "backend": result['backend'],
            "authenticated_via": peer_spiffe_id,
            "mtls_verified": True,
            "gateway": "llm-gateway"
        })
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/validate', methods=['POST'])
def validate_threat():
    """Validate threat assessments using LLM"""
    peer_spiffe_id = extract_peer_spiffe_id()
    if not peer_spiffe_id:
        return jsonify({"error": "Authentication failed"}), 403
    if not authorize_peer(peer_spiffe_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    threat_assessment = request.json.get('assessment', '')
    if not threat_assessment:
        return jsonify({"error": "No assessment provided"}), 400
    
    logger.info(f"📥 Validation request from: {peer_spiffe_id}")
    
    system_prompt = """You are a security threat validator. Review the given threat assessment and determine if it's VALID or INVALID.
Consider:
- Logical consistency
- Severity appropriateness
- Evidence quality

Respond with: VALID or INVALID, followed by brief reasoning."""
    
    try:
        result = call_llm([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Validate this assessment: {threat_assessment}"}
        ], temperature=0.3, max_tokens=500)
        
        validation = result['content']
        is_valid = "VALID" in validation.upper() and "INVALID" not in validation.upper()
        
        logger.info(f"✅ Validation: {'VALID' if is_valid else 'INVALID'} via {result['backend']}")
        
        return jsonify({
            "is_valid": is_valid,
            "validation": validation,
            "model": result['model'],
            "backend": result['backend'],
            "authenticated_via": peer_spiffe_id,
            "mtls_verified": True,
            "gateway": "llm-gateway"
        })
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    logger.info("=" * 70)
    logger.info("LLM Gateway - Multi-Provider mTLS Implementation")
    logger.info("=" * 70)
    logger.info(f"🔧 LLM Backend: {LLM_BACKEND.upper()}")
    
    if LLM_BACKEND == 'gemini':
        logger.info(f"🤖 Model: {GEMINI_MODEL}")
        logger.info(f"🔑 API Key: {'***' + GEMINI_API_KEY[-4:] if GEMINI_API_KEY else 'NOT SET!'}")
        if not GEMINI_API_KEY:
            logger.error("❌ GEMINI_API_KEY environment variable not set!")
            logger.error("   Set it with: export GEMINI_API_KEY='your-key-here'")
            sys.exit(1)
    else:
        logger.info(f"🏠 LM Studio URL: {LM_STUDIO_URL}")
        logger.info(f"🤖 Model: {LM_MODEL}")
    
    logger.info("=" * 70)
    
    # Initialize SPIFFE mTLS
    mtls_handler = SPIFFEMTLSHandler()
    
    if not mtls_handler.x509_svid:
        logger.error("❌ CRITICAL: Failed to obtain SPIFFE certificate!")
        sys.exit(1)
    
    logger.info(f"✅ SPIFFE ID: {mtls_handler.spiffe_id}")
    logger.info(f"✅ mTLS: ENABLED")
    logger.info("=" * 70)
    
    ssl_context = mtls_handler.create_ssl_context()
    
    logger.info(f"✅ Starting HTTPS server on port 8446")
    logger.info(f"✅ Client certificate verification: REQUIRED")
    logger.info(f"✅ Authorized callers: threat-classifier, confidence-scorer, threat-validator")
    logger.info("=" * 70)
    
    try:
        server = SSLWSGIServer(('0.0.0.0', 8446), SSLWSGIRequestHandler, ssl_context)
        server.set_app(app)
        logger.info("✅ Server started successfully")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        for f in [mtls_handler.cert_file, mtls_handler.key_file, mtls_handler.bundle_file]:
            if f:
                try:
                    os.unlink(f.name)
                except:
                    pass
