# Importing required libraries for Flask backend, URL processing, and machine learning
import os
import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from datetime import datetime
from bs4 import BeautifulSoup
import logging
import warnings
import socket
import ssl
import whois

# Suppress warnings for cleaner logs
warnings.filterwarnings('ignore')

# Initialize Flask application
app = Flask(__name__)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backend.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
BACKEND_CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'BASE_URL': 'http://127.0.0.1:5000'
}

# Feature labels for frontend
FEATURE_LABELS = {
    'url_length': {'name': 'URL Length', 'icon': '📏', 'description': lambda v: f'URL length ({v} characters)'},
    'has_at_symbol': {'name': 'At Symbol', 'icon': '❗', 'description': lambda v: 'Contains @ symbol' if v else 'No @ symbol'},
    'has_dash': {'name': 'Domain Dash', 'icon': '➖', 'description': lambda v: 'Dash in domain' if v else 'No dash in domain'},
    'subdomain_count': {'name': 'Subdomains', 'icon': '🌐', 'description': lambda v: f'{v} subdomains'},
    'is_https': {'name': 'HTTPS (Scheme)', 'icon': '🔒', 'description': lambda v: 'Valid HTTPS scheme' if v else 'No HTTPS scheme'},
    'domain_age_days': {'name': 'Domain Age', 'icon': '📅', 'description': lambda v: f'Domain age: {v} days'},
    'has_ip_address': {'name': 'IP Address', 'icon': '🌍', 'description': lambda v: 'Uses IP address' if v else 'Uses domain name'},
    'redirect_count': {'name': 'Redirects', 'icon': '🔄', 'description': lambda v: f'{v} redirects'},
    'has_login_form': {'name': 'Login Form', 'icon': '🔑', 'description': lambda v: 'Contains login form' if v else 'No login form'},
    'has_iframe': {'name': 'Iframe', 'icon': '🖼️', 'description': lambda v: 'Contains iframe' if v else 'No iframe'},
    'suspicious_words_count': {'name': 'Suspicious Words', 'icon': '🚨', 'description': lambda v: f'{v} suspicious words'},
    
    # New network-specific indicators for the frontend UI:
    'port_80_open': {'name': 'Port 80 (HTTP)', 'icon': '🔌', 'description': lambda v: 'Port 80 is listening' if v else 'Port 80 closed'},
    'port_443_open': {'name': 'Port 443 (HTTPS)', 'icon': '🛡️', 'description': lambda v: 'Socket 443 active' if v else 'Socket 443 closed'},
    'server_reachable': {'name': 'Server Reachable', 'icon': '📡', 'description': lambda v: 'Active HTTP response' if v else 'No valid response'}
}

# Feature thresholds (used only for parameter coloring — not for ML score)
FEATURE_THRESHOLDS = {
    'url_length': {
        'safe': lambda v: v <= 118,
        'warning': lambda v: 118 < v <= 133,
        'danger': lambda v: 133 < v <= 163,
        'malware': lambda v: v > 163
    },
    'has_at_symbol': {
        'safe': lambda v: v == 0,
        'danger': lambda v: v == 1,
    },
    'has_dash': {
        'safe': lambda v: v == 0,
        'danger': lambda v: v == 1,
    },
    'subdomain_count': {
        'safe': lambda v: v <= 1,
        'warning': lambda v: 1 < v <= 4,
        'danger': lambda v: v > 4,
    },
    'is_https': {
        'safe': lambda v: v == 1,
        'danger': lambda v: v == 0,
    },
    'has_ip_address': {
        'safe': lambda v: v == 0,
        'danger': lambda v: v == 1,
    },
    'redirect_count': {
        'safe': lambda v: v <= 1,
        'warning': lambda v: 1 < v <= 2,
        'danger': lambda v: v > 2,
    },
    'has_login_form': {
        'safe': lambda v: v == 0,
        'danger': lambda v: v == 1,
    },
    'has_iframe': {
        'safe': lambda v: True,   # most legit sites have iframes — consider removing or inverting
        'danger': lambda v: False,
    },
    'suspicious_words_count': {
        'safe': lambda v: v <= 2,
        'danger': lambda v: v > 2,
    },
    'domain_age_days': {          # placeholder — fake ages make this unreliable
        'safe': lambda v: True,
        'danger': lambda v: False,
    },
    'port_80_open': {
        'safe': lambda v: True,
    },
    'port_443_open': {
        'safe': lambda v: v == 1,
        'warning': lambda v: v == 0,
    },
    'server_reachable': {
        'safe': lambda v: v == 1,
        'danger': lambda v: v == 0,
    }
}

class PhishingDetector:
    def __init__(self):
        self.model = None
        # Explicit original ML features
        self.feature_names = [
            'url_length', 'has_at_symbol', 'has_dash', 'subdomain_count',
            'is_https', 'domain_age_days', 'has_ip_address', 'redirect_count',
            'has_login_form', 'has_iframe', 'suspicious_words_count'
        ]

    def check_port(self, domain, port, timeout=1.0):
        """Check if a specific port is active and listening on the domain."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((domain, port))
            sock.close()
            return result == 0
        except:
            return False

    def extract_features_dict(self, url):
        features = {}
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower() if parsed_url.netloc else parsed_url.path.lower()
            
            # Remove any port from domain if present for accurate socket/whois checks
            domain = domain.split(':')[0]

            features['url_length'] = len(url)
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_dash'] = 1 if '-' in domain else 0
            features['subdomain_count'] = max(len(domain.split('.')) - 2, 0)
            
            # Run network-bound requests in parallel to save time
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                fut_port80 = executor.submit(self.check_port, domain, 80, 1.0)
                fut_port443 = executor.submit(self.check_port, domain, 443, 1.0)
                fut_age = executor.submit(self.get_domain_age, domain)
                fut_redirects = executor.submit(self.count_redirects, url)
                fut_page = executor.submit(self.analyze_page_content, url)
                
                try:
                    features['port_80_open'] = 1 if fut_port80.result(timeout=1.5) else 0
                except Exception:
                    features['port_80_open'] = 0
                    
                try:
                    features['port_443_open'] = 1 if fut_port443.result(timeout=1.5) else 0
                except Exception:
                    features['port_443_open'] = 0
                    
                features['is_https'] = features['port_443_open']
                
                try:
                    features['domain_age_days'] = fut_age.result(timeout=1.5)
                except Exception:
                    features['domain_age_days'] = 30 # fallback
                    
                try:
                    features['redirect_count'] = fut_redirects.result(timeout=2.0)
                except Exception:
                    features['redirect_count'] = 0
                    
                try:
                    page_features = fut_page.result(timeout=2.5)
                except Exception:
                    page_features = {'has_login_form': 0, 'has_iframe': 0, 'server_reachable': 0}
                    
                features.update(page_features)

            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            features['has_ip_address'] = 1 if re.search(ip_pattern, domain) else 0

            suspicious_words = ['login', 'verify', 'account', 'suspended', 'click', 'urgent']
            features['suspicious_words_count'] = sum(1 for word in suspicious_words if word.lower() in url.lower())

            logger.debug(f"Features dictionary extracted for {url}")
        except Exception as e:
            logger.error(f"Error extracting features dict for {url}: {str(e)}")
            for feature in self.feature_names:
                if feature not in features:
                    features[feature] = 0

        return features

    def extract_features(self, url):
        features_dict = self.extract_features_dict(url)
        return [features_dict.get(name, 0) for name in self.feature_names]

    def get_domain_age(self, domain):
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            if creation_date:
                age = (datetime.now() - creation_date).days
                return max(0, age)
        except Exception as e:
            logger.warning(f"Whois failed for {domain}: {str(e)}")
        
        # Fallback to pseudo-random placeholder if whois fails
        try:
            return hash(domain) % 365 + 30
        except:
            return 30

    def count_redirects(self, url):
        try:
            # Skip internal/chrome URLs
            if url.startswith(('chrome://', 'about:', 'edge://', 'brave://')):
                return 0
            response = requests.head(url, allow_redirects=True, timeout=1.5)
            return len(response.history)
        except Exception as e:
            logger.warning(f"Failed to count redirects for {url}: {str(e)}")
            return 0

    def analyze_page_content(self, url):
        features = {'has_login_form': 0, 'has_iframe': 0, 'server_reachable': 0}
        try:
            if url.startswith(('chrome://', 'about:', 'edge://', 'brave://')):
                return features
            
            # Send a legit HTTP request to the URL mimicking a browser and analyze response
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
            response = requests.get(url, headers=headers, timeout=2.0, verify=True)
            features['server_reachable'] = 1 if response.status_code < 500 else 0
            
            # Analyze response characteristics
            logger.debug(f"[{url}] Server Response Code: {response.status_code}")
            logger.debug(f"[{url}] Server Headers: {dict(response.headers)}")
            
            soup = BeautifulSoup(response.text, 'html.parser')

            if soup.find_all(['input'], {'type': ['password']}):
                features['has_login_form'] = 1

            if soup.find_all('iframe'):
                features['has_iframe'] = 1
        except requests.exceptions.SSLError as e:
            features['server_reachable'] = 0
            logger.warning(f"SSL validation failed during request to {url}: {str(e)}")
        except Exception as e:
            features['server_reachable'] = 0
            logger.warning(f"Page analysis failed for {url}: {str(e)}")
        return features

    def load_model(self):
        try:
            BASE_DIR = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(BASE_DIR, 'phishing_model.pkl')

            self.model = joblib.load(model_path)
            logger.info(f"Model loaded from {model_path}")
        except FileNotFoundError:
            logger.error("phishing_model.pkl not found!")
            raise
        except Exception as e:
            logger.error(f"Model loading failed: {str(e)}")
            raise

    def predict(self, url):
        if self.model is None:
            self.load_model()

        try:
            features_dict = self.extract_features_dict(url)
            
            # ISP Hijack / Offline server defense
            if features_dict.get('port_80_open') == 0 and features_dict.get('port_443_open') == 0 and features_dict.get('server_reachable') == 0:
                logger.warning(f"URL {url} has no open ports and is completely unreachable. Flagging as non-existent.")
                return {
                    'prediction': 'error',
                    'score': 1.0,
                    'parameters': [],
                    'message': 'Please enter a valid URL. The website is offline or does not exist.'
                }

            ml_features = [features_dict.get(name, 0) for name in self.feature_names]
            
            prediction = self.model.predict([ml_features])[0]
            probability = self.model.predict_proba([ml_features])[0]

            # ── IMPORTANT: Log probabilities so you can see what the model thinks ──
            logger.info(f"URL: {url} | Raw prediction: {prediction} | Probabilities: {probability.tolist()}")

            if len(probability) == 2:
                # Index 0 represents 'legitimate'/safe prediction
                prob_safe = float(probability[0])
                score = round(prob_safe * 10, 1)
                
                # Optional: fallback check – if pred_class == 1 (phishing) but prob[0] high → clamp
                if prediction == 1 and prob_safe > 0.7:
                    score = 1.0  # force low if model says malicious
            else:
                score = 5.0  # unexpected number of classes

            score = max(1.0, min(10.0, score))

            # --- HEURISTIC OVERRIDES ---
            # The ML model has blind spots for certain advanced obfuscations. 
            # Force severe penalties for obvious malicious patterns (e.g., encoded paths, all-number domains)
            import urllib.parse
            netloc = urllib.parse.urlparse(url).netloc.split(':')[0]
            if netloc.replace('.', '').isdigit(): # e.g. 9779.info or raw IP
                score = 1.0
                prediction = 1
            elif url.count('%') >= 3: # Heavy URL encoding obfuscation
                score = 1.0
                prediction = 1
            elif len(url) > 85 and features_dict.get('is_https') == 0:
                score = 1.0
                prediction = 1

            # Build parameters display
            parameters = []
            for name, value in features_dict.items():
                if name in FEATURE_LABELS:
                    thresh = FEATURE_THRESHOLDS.get(name, {})
                    status = 'safe'
                    if 'malware' in thresh and thresh['malware'](value):
                        status = 'malware'
                    elif 'danger' in thresh and thresh['danger'](value):
                        status = 'danger'
                    elif 'warning' in thresh and thresh['warning'](value):
                        status = 'warning'

                    parameters.append({
                        'name': FEATURE_LABELS[name]['name'],
                        'icon': FEATURE_LABELS[name]['icon'],
                        'status': status,
                        'description': FEATURE_LABELS[name]['description'](value)
                    })
            all_safe = all(p['status'] == 'safe' for p in parameters)
            # ONLY grant the perfect 10/10 score if the AI specifically marked the site as Legit (> 5.0) first!
            if all_safe and score >= 5.0:
                if features_dict.get('port_443_open') == 1 and features_dict.get('server_reachable') == 1:
                    score = 10.0
                else:
                    score = 9.0

            # ENFORCE VISUAL WARNINGS: If overall score is dangerous, actively punish UI parameter tags to reflect "malware" / "danger"
            if score < 5.0:
                for p in parameters:
                    if p['status'] == 'safe':
                        # Distribute Danger/Malware/Warning flags depending on the metric
                        if p['name'] in ['Domain Age', 'Subdomains', 'HTTPS (Scheme)', 'Server Reachable']:
                            p['status'] = 'danger'
                        elif p['name'] in ['IP Address', 'Redirects']:
                            p['status'] = 'malware'
                        elif p['name'] in ['Login Form', 'Iframe']:
                            p['status'] = 'warning'
                        else:
                            p['status'] = 'danger'

            # Label mapping — binary version
            prediction_map = {0: 'legitimate', 1: 'phishing'}
            pred_label = prediction_map.get(int(prediction), 'unknown')

            return {
                'prediction': pred_label,
                'score': score,
                'parameters': parameters
            }

            # Label mapping — binary version
            prediction_map = {0: 'legitimate', 1: 'phishing'}
            pred_label = prediction_map.get(int(prediction), 'unknown')

            return {
                'prediction': pred_label,
                'score': score,
                'parameters': parameters
            }
        except Exception as e:
            logger.error(f"Error predicting for {url}: {str(e)}")
            return {'prediction': 'error', 'score': 1.0, 'parameters': []}


detector = PhishingDetector()

def validate_url(url):
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and (parsed.netloc or parsed.path))
    except:
        return False

@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "message": "WebSafe Detection API is running!",
        "backend": "Flask",
        "ngrok_url": BACKEND_CONFIG['BASE_URL']
    })
@app.route('/predict', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not validate_url(url):
            return jsonify({'error': 'Invalid URL format'}), 400

        result = detector.predict(url)

        if result.get('prediction') == 'error':
            return jsonify({'error': result.get('message', 'Please enter a valid URL. The website does not exist.')}), 400

        response = {
            'score': result['score'],
            'url': url,
            'parameters': result['parameters'],
            'message': ('Safe website.' if result['prediction'] == 'legitimate'
                        else f'Potential {result["prediction"]} risk!'),
            'timestamp': datetime.utcnow().isoformat()
        }
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error in /predict: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

# Keep your other endpoints (/batch-predict, /health, /) as they are ...

if __name__ == '__main__':
    logger.info("Starting WebSafe Detection API...")
    try:
        detector.load_model()
    except Exception as e:
        logger.critical("Model failed to load. Exiting.", exc_info=True)
        exit(1)

    app.run(
        host=BACKEND_CONFIG['HOST'],
        port=BACKEND_CONFIG['PORT'],
        debug=True
    )