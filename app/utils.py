# ZeroTrust_AI_Project/app/utils.py
import os
import logging
from cryptography.fernet import Fernet
import sys
import io  # <<< Add this import
import tensorflow as tf # <<< Add this import

# Ensure the main project directory is in the path to import config
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import (MODEL_ENCRYPTION_KEY, ORIGINAL_MODEL_PATH, ENCRYPTED_MODEL_PATH,
                            LOG_DIR, LOG_FILE, LOG_LEVEL, TEMP_DECRYPTED_PATH) # <<< Add TEMP_DECRYPTED_PATH
except ImportError as e:
    print(f"Error importing from config: {e}. Ensure config.py exists and is in the Python path.")
    sys.exit(1)


# --- Initialize Cipher ---
try:
    cipher_suite = Fernet(MODEL_ENCRYPTION_KEY)
except Exception as e:
    logging.error(f"FATAL: Failed to initialize cipher suite. Check MODEL_ENCRYPTION_KEY. Error: {e}", exc_info=True)
    sys.exit(1) # Cannot proceed without cipher


# --- Logging Setup ---
def setup_logging():
    # ... (keep existing setup_logging function) ...
    os.makedirs(LOG_DIR, exist_ok=True)
    log_level_enum = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level_enum,
        format='%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.info("Logging initialized.")


# --- File Encryption/Decryption ---
def encrypt_model_file(source_path=ORIGINAL_MODEL_PATH, dest_path=ENCRYPTED_MODEL_PATH):
    # ... (keep existing encrypt_model_file function) ...
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"Attempting to encrypt model from {os.path.basename(source_path)} to {os.path.basename(dest_path)}")
        if not os.path.exists(source_path):
            logger.error(f"Encryption failed: Source model file not found at {source_path}")
            return False
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(source_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(dest_path, 'wb') as file:
            file.write(encrypted_data)
        logger.info(f"Model successfully encrypted to {os.path.basename(dest_path)}")
        return True
    except Exception as e:
        logger.error(f"Encryption failed: {e}", exc_info=True)
        return False

def decrypt_data(encrypted_path=ENCRYPTED_MODEL_PATH):
    # ... (keep existing decrypt_data function) ...
    logger = logging.getLogger(__name__)
    try:
        logger.debug(f"Attempting to decrypt model from {os.path.basename(encrypted_path)}")
        if not os.path.exists(encrypted_path):
            logger.error(f"Decryption failed: Encrypted model file not found at {encrypted_path}")
            return None
        with open(encrypted_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        logger.debug(f"Model data successfully decrypted from {os.path.basename(encrypted_path)}")
        return decrypted_data
    except Exception as e:
        logger.error(f"Decryption failed: {e}", exc_info=True)
        return None

# --- Model Loading Utility --- <<< NEW FUNCTION >>>
def load_keras_model_from_bytes(model_bytes):
    """Loads a Keras model from decrypted bytes."""
    logger = logging.getLogger(__name__)
    try:
        # Saving decrypted data to a temporary file might be more reliable
        # especially for complex models, than loading directly from bytes buffer.
        logger.debug(f"Writing decrypted model data to temporary file: {TEMP_DECRYPTED_PATH}")
        with open(TEMP_DECRYPTED_PATH, 'wb') as temp_f:
            temp_f.write(model_bytes)

        # Load the model from the temporary file path
        model = tf.keras.models.load_model(TEMP_DECRYPTED_PATH)
        logger.info("Keras model loaded successfully from temporary file.")

        # Clean up the temporary file
        try:
            os.remove(TEMP_DECRYPTED_PATH)
            logger.debug(f"Removed temporary model file: {TEMP_DECRYPTED_PATH}")
        except OSError as e:
            logger.warning(f"Could not remove temporary model file {TEMP_DECRYPTED_PATH}: {e}")

        return model
    except Exception as e:
        logger.error(f"Failed to load Keras model from bytes/temp file: {e}", exc_info=True)
        # Attempt cleanup even on failure
        if os.path.exists(TEMP_DECRYPTED_PATH):
             try:
                 os.remove(TEMP_DECRYPTED_PATH)
             except OSError:
                 pass # Ignore cleanup error if loading failed
        return None


# --- Initial Encryption Runner ---
if __name__ == "__main__":
    # ... (keep existing __main__ block) ...
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Running initial model encryption check...")
    # ...(rest of __main__ block)...