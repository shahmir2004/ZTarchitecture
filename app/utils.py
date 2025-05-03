# ZeroTrust_AI_Project/app/utils.py
import os
import logging
from pythonjsonlogger import jsonlogger # <<< Import
from cryptography.fernet import Fernet
import sys
import io
import tensorflow as tf

# Ensure the main project directory is in the path to import config
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import (MODEL_ENCRYPTION_KEY, ORIGINAL_MODEL_PATH, ENCRYPTED_MODEL_PATH,
                            LOG_DIR, LOG_FILE, LOG_LEVEL, TEMP_DECRYPTED_PATH)
except ImportError as e:
    print(f"Error importing from config: {e}. Ensure config.py exists and is in the Python path.")
    sys.exit(1)


# --- Initialize Cipher ---
try:
    cipher_suite = Fernet(MODEL_ENCRYPTION_KEY)
except Exception as e:
    # Use basic logging before setup_logging is called if needed
    logging.basicConfig(level=logging.ERROR)
    logging.error(f"FATAL: Failed to initialize cipher suite. Check MODEL_ENCRYPTION_KEY. Error: {e}", exc_info=True)
    sys.exit(1)


# --- Logging Setup (Modified for JSON) ---
def setup_logging():
    """Configures application logging using JSON format."""
    os.makedirs(LOG_DIR, exist_ok=True)
    log_level_enum = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger = logging.getLogger()

    if logger.hasHandlers():
        logger.handlers.clear()

    log_format = '%(asctime)s %(levelname)s %(name)s %(message)s %(pathname)s %(lineno)d'
    formatter = jsonlogger.JsonFormatter(log_format)

    logHandler = logging.FileHandler(LOG_FILE)
    logHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    logger.addHandler(logHandler)
    logger.addHandler(streamHandler)
    logger.setLevel(log_level_enum)
    logger.propagate = False

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    # Use root logger for initial message, pass data via extra
    logger.info("Logging initialized", extra={'event_type': 'logging_init', 'log_level': LOG_LEVEL, 'log_file': LOG_FILE})


# --- File Encryption/Decryption ---
def encrypt_model_file(source_path=ORIGINAL_MODEL_PATH, dest_path=ENCRYPTED_MODEL_PATH):
    """Encrypts the source file to the destination file."""
    logger = logging.getLogger(__name__)
    event_data = {'source_path': source_path, 'dest_path': dest_path, 'event_type': 'encrypt_attempt'}
    try:
        logger.info("Attempting model encryption", extra=event_data)
        if not os.path.exists(source_path):
            logger.error("Encryption failed: Source model file not found", extra=event_data)
            return False

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(source_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(dest_path, 'wb') as file:
            file.write(encrypted_data)

        event_data['event_type'] = 'encrypt_success' # Update status
        logger.info("Model successfully encrypted", extra=event_data)
        return True
    except Exception as e:
        event_data['event_type'] = 'encrypt_fail'
        event_data['error'] = str(e)
        logger.error(f"Encryption failed", extra=event_data, exc_info=True) # exc_info adds traceback
        return False

def decrypt_data(encrypted_path=ENCRYPTED_MODEL_PATH):
    """Decrypts file and returns the decrypted data bytes. Returns None on failure."""
    logger = logging.getLogger(__name__)
    event_data = {'encrypted_path': encrypted_path, 'event_type': 'decrypt_attempt'}
    try:
        logger.debug("Attempting model decryption", extra=event_data)
        if not os.path.exists(encrypted_path):
            logger.error("Decryption failed: Encrypted model file not found", extra=event_data)
            return None

        with open(encrypted_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        event_data['event_type'] = 'decrypt_success'
        logger.debug("Model data successfully decrypted", extra=event_data)
        return decrypted_data
    except Exception as e:
        event_data['event_type'] = 'decrypt_fail'
        event_data['error'] = str(e)
        logger.error(f"Decryption failed", extra=event_data, exc_info=True)
        return None

# --- Model Loading Utility ---
def load_keras_model_from_bytes(model_bytes):
    """Loads a Keras model from decrypted bytes."""
    logger = logging.getLogger(__name__)
    event_data = {'event_type': 'model_load_attempt', 'temp_path': TEMP_DECRYPTED_PATH}
    try:
        logger.debug(f"Writing decrypted model data to temporary file", extra=event_data)
        with open(TEMP_DECRYPTED_PATH, 'wb') as temp_f:
            temp_f.write(model_bytes)

        model = tf.keras.models.load_model(TEMP_DECRYPTED_PATH)

        event_data['event_type'] = 'model_load_success'
        logger.info("Keras model loaded successfully from temporary file.", extra=event_data)

        # Clean up the temporary file
        try:
            os.remove(TEMP_DECRYPTED_PATH)
            logger.debug(f"Removed temporary model file", extra=event_data)
        except OSError as e:
            logger.warning(f"Could not remove temporary model file", extra={**event_data, 'error': str(e)})

        return model
    except Exception as e:
        event_data['event_type'] = 'model_load_fail'
        event_data['error'] = str(e)
        logger.error(f"Failed to load Keras model from bytes/temp file", extra=event_data, exc_info=True)
        if os.path.exists(TEMP_DECRYPTED_PATH):
             try:
                 os.remove(TEMP_DECRYPTED_PATH)
             except OSError: pass
        return None


# --- Initial Encryption Runner ---
if __name__ == "__main__":
    setup_logging() # Initialize logging first
    logger = logging.getLogger(__name__) # Get logger after setup
    logger.info("Running initial model encryption check", extra={'event_type': 'setup_check'})
    # ...(keep existing __main__ block, its logging calls will now be JSON)...
    if os.path.exists(ORIGINAL_MODEL_PATH):
        logger.info("Found original model", extra={'path': ORIGINAL_MODEL_PATH})
        if not os.path.exists(ENCRYPTED_MODEL_PATH):
            logger.warning("Encrypted model not found", extra={'path': ENCRYPTED_MODEL_PATH})
            logger.info("Attempting initial encryption", extra={'event_type': 'initial_encrypt_start'})
            if encrypt_model_file():
                logger.info("Initial model encryption successful.")
            else:
                logger.error("Initial model encryption FAILED.")
        else:
            logger.info("Encrypted model already exists. Skipping initial encryption.")
    else:
        logger.error("Original model file not found", extra={'path': ORIGINAL_MODEL_PATH, 'event_type': 'setup_fail'})