# ZeroTrust_AI_Project/config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Sensitive Config (Loaded from .env) ---
# WARNING: Acknowledge key management risks in report.
MODEL_ENCRYPTION_KEY_STR = os.getenv('MODEL_ENCRYPTION_KEY')
if not MODEL_ENCRYPTION_KEY_STR:
    raise ValueError("MODEL_ENCRYPTION_KEY not found in .env file or environment variables.")
MODEL_ENCRYPTION_KEY = MODEL_ENCRYPTION_KEY_STR.encode() # Convert to bytes

FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default_fallback_secret_key') # Use a fallback only if necessary


# --- Load Admin OTP ---
ADMIN_OTP = os.getenv('ADMIN_OTP_SECRET')
# ... (keep warning/fallback for ADMIN_OTP if using static) ...

# --- Load Mail Configuration --- <<< ADD or VERIFY THIS SECTION <<<
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't', 'yes'] # Default to True if not set
MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False').lower() in ['true', '1', 't', 'yes'] # Default to False
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') # Your App Password or Gmail password
MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME) # Default sender to username if not set
# ------------------------


# --- General Config ---
# Get the absolute path of the directory the config file is in
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define model paths relative to BASE_DIR
MODEL_DIR = os.path.join(BASE_DIR, 'models')
DECRYPTED_MODEL_NAME = 'mnist_cnn_defended_adv_train.keras' # Original/Decrypted name
ENCRYPTED_MODEL_NAME = DECRYPTED_MODEL_NAME + '.enc' # Encrypted version name

# Construct full paths
ORIGINAL_MODEL_PATH = os.path.join(MODEL_DIR, DECRYPTED_MODEL_NAME)
ENCRYPTED_MODEL_PATH = os.path.join(MODEL_DIR, ENCRYPTED_MODEL_NAME)
TEMP_DECRYPTED_PATH = os.path.join(MODEL_DIR, 'temp_' + DECRYPTED_MODEL_NAME) # Temp path for decryption

# Logging configuration
LOG_DIR = os.path.join(BASE_DIR, 'logs') # Store logs in a logs/ directory
LOG_FILE = os.path.join(LOG_DIR, 'activity.log')
LOG_LEVEL = 'INFO' # e.g., DEBUG, INFO, WARNING

# Token Expiry (optional)
TOKEN_EXPIRY_DURATION_SECONDS = 3600 # 1 hour