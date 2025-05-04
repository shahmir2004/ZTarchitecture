# ZeroTrust_AI_Project/app/auth.py
import os
import sys
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import time
import logging
import random 
import string

# --- NEW: Temporary OTP Store --- (Make sure this exists too)
PENDING_MFA = {}
MFA_OTP_EXPIRY_SECONDS = 120 # OTP is valid for 2 minutes
MFA_OTP_LENGTH = 5 # Make OTP 5 digits long
# -----------------------------

def generate_and_store_otp(username):
    """Generates a random OTP, stores it temporarily for the user."""
    if not username: return None
    otp = "".join(random.choices(string.digits, k=MFA_OTP_LENGTH)) # Generate 5 random digits
    expires_at = time.time() + MFA_OTP_EXPIRY_SECONDS
    PENDING_MFA[username] = {'otp': otp, 'expires_at': expires_at}
    # Logging call is here from previous step
    logger.info("Generated temporary MFA OTP", extra={'user_id': username, 'event_type': 'mfa_otp_generated', 'expires_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))})
    return otp 

def verify_otp(username, provided_otp):
    """Verifies a provided OTP against the stored temporary one."""
    event_data = {'user_id': username, 'event_type': 'mfa_otp_verify_attempt'}
    logger.debug("Attempting MFA OTP verification", extra=event_data) # Added debug
    pending = PENDING_MFA.get(username)

    if not pending:
        event_data['fail_reason'] = 'no_pending_mfa'
        logger.warning("No pending MFA found for user during verification", extra=event_data)
        return False # No pending MFA for this user

    if time.time() > pending['expires_at']:
        event_data['fail_reason'] = 'otp_expired'
        logger.warning("MFA OTP has expired", extra=event_data)
        try: # Attempt to clean up expired entry
            del PENDING_MFA[username]
        except KeyError: pass # Ignore if already deleted elsewhere
        return False # Expired

    # Compare the OTP stored with the one provided by the user
    if pending['otp'] == provided_otp:
        event_data['event_type'] = 'mfa_otp_verify_success'
        logger.info("MFA OTP verified successfully", extra=event_data)
        try: # Clean up used entry
            del PENDING_MFA[username]
        except KeyError: pass # Ignore if already deleted
        return True # OTP Match
    else:
        event_data['fail_reason'] = 'otp_mismatch'
        logger.warning("Invalid MFA OTP provided", extra=event_data)
        # Optional: Implement lockout after too many failed OTP attempts
        # For now, just fail the current attempt
        return False # OTP Mismatch

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

USERS = {
    "predictor01": {
        "hash": "scrypt:32768:8:1$YJWVy9xPtmEBtWwi$8f0feeb7d0ffed7834fc6f441cb92ff87114f8002ee2dbf83961ef15f63d5685daff0a1e6ff902ee4e37c2bec7c44c23a2f8d2cf0bb1f9a7c3e1e5173a9b9871", # Password was PredictPass123
        "role": "predictor"
    },
    "admin01": {
        "hash": "scrypt:32768:8:1$i3TbaVTQs2fnLzb9$a5316124f41d26e6285ce6c92656e69ef1aa9f537bb8fec9c8a528d6c73a91d62ac1d9955b50872f30c5e5cd66dec49779f8ce24ca0b1162fd30ba94cefc483f", # Password was AdminPass123
        "role": "admin"
    },
    "myztprojectsender@gmail.com": {
        "hash":"scrypt:32768:8:1$DeCWBarIFLUSkv2f$788f0bf4cce23f503097d408b0698754ff42417562406c76b5d71852ec43de580e2484e223996fe2cd867f4d0fb4c444e1bce0d326aceeedd3e663fede1dd282",
        "role":"admin"
    }
}


# --- Simulated Active Tokens Store ---
ACTIVE_TOKENS = {} # Format: { 'token': {'user_id': ..., 'role': ..., 'expires_at': ...} }

# --- Functions ---
def verify_password(username, provided_password):
    """Checks if the provided password matches the stored hash for the user."""
    event_data = {'username_attempted': username, 'event_type': 'password_verify'}
    logger.debug("Verifying password", extra=event_data)
    user = USERS.get(username)
    if user:
        stored_hash = user["hash"]
        # logger.debug(f"Found user. Stored hash starts with: {stored_hash[:20]}...") # Avoid logging hash info
        is_match = check_password_hash(stored_hash, provided_password)
        event_data['match_result'] = is_match
        logger.debug("Password match result calculated", extra=event_data)
        return is_match
    else:
        event_data['event_type'] = 'password_verify_fail' # Adjusted type
        event_data['reason'] = 'user_not_found'
        logger.warning("User not found in store during password verification", extra=event_data)
        return False


def get_user_role(username):
    """Retrieves the role for a given username."""
    user = USERS.get(username)
    return user["role"] if user else None

def generate_token(username):
    """Generates a simple unique token and stores it with user info."""
    role = get_user_role(username)
    event_data = {'user_id': username, 'role': role, 'event_type': 'token_generate'}
    if not role:
        logger.error("Cannot generate token for unknown user/role", extra=event_data)
        return None

    token = str(uuid.uuid4())
    expires_at = time.time() + TOKEN_EXPIRY_DURATION_SECONDS
    ACTIVE_TOKENS[token] = {
        'user_id': username,
        'role': role,
        'expires_at': expires_at
    }
    expires_at_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))
    event_data['expires_at'] = expires_at_str
    event_data['event_type'] = 'token_generate_success' # Adjusted
    logger.info("Token generated", extra=event_data)
    # Avoid logging the token itself unless needed for debugging with care
    # event_data['token'] = token
    
    return token

def verify_token(token):
    """Checks if a token is valid and not expired. Returns user info or None."""
    event_data = {'token_provided': token, 'event_type': 'token_verify'}
    if token in ACTIVE_TOKENS:
        token_data = ACTIVE_TOKENS[token]
        event_data.update({'user_id': token_data.get('user_id'), 'role': token_data.get('role')}) # Add context
        if time.time() < token_data['expires_at']:
            logger.debug("Token verified", extra=event_data)
            return token_data # Return {'user_id': ..., 'role': ..., 'expires_at': ...}
        else:
            event_data['event_type'] = 'token_expired'
            logger.warning("Attempt to use expired token", extra=event_data)
            # Clean up expired token
            del ACTIVE_TOKENS[token]
            return None # Expired
    # Log invalid token attempts less verbosely perhaps, or at DEBUG level
    logger.debug("Invalid or unknown token provided.", extra=event_data)
    return None # Invalid or not found

def invalidate_token(token):
    """Removes a token from the active store (logout)."""
    event_data = {'token_provided': token, 'event_type': 'token_invalidate_attempt'} # Adjusted
    if token in ACTIVE_TOKENS:
        user_id = ACTIVE_TOKENS[token].get('user_id', 'unknown')
        event_data['user_id'] = user_id
        del ACTIVE_TOKENS[token]
        event_data['event_type'] = 'token_invalidate_success' # Adjusted
        logger.info("Token invalidated (Logout)", extra=event_data)
        return True
    event_data['event_type'] = 'token_invalidate_fail' # Adjusted
    logger.warning("Attempt to invalidate non-existent token", extra=event_data)
    return False

# --- RBAC Helper ---
def check_permission(required_role, user_role):
    """Checks if user_role meets the required_role."""
    # No logging needed here usually, context is in the calling function
    if not user_role:
        return False
    if user_role == 'admin':
        return True
    return user_role == required_role