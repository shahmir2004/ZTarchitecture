# ZeroTrust_AI_Project/app/auth.py
import os
import sys
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import time
import logging

# Ensure the main project directory is in the path to import config
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import TOKEN_EXPIRY_DURATION_SECONDS
except ImportError as e:
    print(f"Error importing from config: {e}. Ensure config.py exists and is in the Python path.")
    sys.exit(1)

logger = logging.getLogger(__name__)

# --- Simulated User Store ---
# Replace example hashes with ones you generate for your chosen passwords
# python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YourSecurePassword'))"
USERS = {
    "predictor01": {
        "hash": "scrypt:32768:8:1$YJWVy9xPtmEBtWwi$8f0feeb7d0ffed7834fc6f441cb92ff87114f8002ee2dbf83961ef15f63d5685daff0a1e6ff902ee4e37c2bec7c44c23a2f8d2cf0bb1f9a7c3e1e5173a9b9871", # Password was PredictPass123
        "role": "predictor"
    },
    "admin01": {
        "hash": "scrypt:32768:8:1$i3TbaVTQs2fnLzb9$a5316124f41d26e6285ce6c92656e69ef1aa9f537bb8fec9c8a528d6c73a91d62ac1d9955b50872f30c5e5cd66dec49779f8ce24ca0b1162fd30ba94cefc483f", # Password was AdminPass123
        "role": "admin"
    },
    "shahmir": {
        "hash":"scrypt:32768:8:1$DeCWBarIFLUSkv2f$788f0bf4cce23f503097d408b0698754ff42417562406c76b5d71852ec43de580e2484e223996fe2cd867f4d0fb4c444e1bce0d326aceeedd3e663fede1dd282",
        "role":"admin"
    }
}


# --- Simulated Active Tokens Store ---
ACTIVE_TOKENS = {} # Format: { 'token': {'user_id': ..., 'role': ..., 'expires_at': ...} }

# --- Functions ---
def verify_password(username, provided_password):
    """Checks if the provided password matches the stored hash for the user."""
    user = USERS.get(username)
    if user and check_password_hash(user["hash"], provided_password):
        return True
    return False

def get_user_role(username):
    """Retrieves the role for a given username."""
    user = USERS.get(username)
    return user["role"] if user else None

def generate_token(username):
    """Generates a simple unique token and stores it with user info."""
    role = get_user_role(username)
    if not role:
        return None # Should not happen if called after successful login

    token = str(uuid.uuid4())
    expires_at = time.time() + TOKEN_EXPIRY_DURATION_SECONDS
    ACTIVE_TOKENS[token] = {
        'user_id': username,
        'role': role,
        'expires_at': expires_at
    }
    logger.info(f"Generated token for user '{username}' (Role: {role}). Expires at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}")
    return token

def verify_token(token):
    """Checks if a token is valid and not expired. Returns user info or None."""
    if token in ACTIVE_TOKENS:
        token_data = ACTIVE_TOKENS[token]
        if time.time() < token_data['expires_at']:
            logger.debug(f"Token verified for user '{token_data['user_id']}' (Role: {token_data['role']})")
            return token_data # Return {'user_id': ..., 'role': ..., 'expires_at': ...}
        else:
            logger.warning(f"Attempt to use expired token for user '{token_data['user_id']}'")
            # Clean up expired token
            del ACTIVE_TOKENS[token]
            return None # Expired
    # logger.debug(f"Invalid or unknown token provided.") # Can be noisy
    return None # Invalid or not found

def invalidate_token(token):
    """Removes a token from the active store (logout)."""
    if token in ACTIVE_TOKENS:
        user_id = ACTIVE_TOKENS[token].get('user_id', 'unknown')
        del ACTIVE_TOKENS[token]
        logger.info(f"Token invalidated for user '{user_id}' (Logout)")
        return True
    return False

# --- RBAC Helper ---
def check_permission(required_role, user_role):
    """Checks if user_role meets the required_role."""
    if not user_role:
        return False
    if user_role == 'admin':
        return True # Admin has all permissions
    return user_role == required_role # Check if role matches exactly