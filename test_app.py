# ZeroTrust_AI_Project/test_app.py (Renamed from test_api.py)

import requests
import numpy as np
import json
import os
import logging
import sys
import time # For potential delays/retries
import pytest # Import pytest
from datetime import datetime # Import datetime class
from urllib.parse import urlparse # Import urlparse

# --- Imports from project ---
# Ensure project root is in path for imports
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
try:
    from config import LOG_FILE # Import log file path
except ImportError:
    print("ERROR: Cannot import from config.py")
    sys.exit(1)

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000" # Keep HTTP for testing unless HTTPS required AND working
LOGIN_URL = f"{BASE_URL}/login"
LOGS_URL = f"{BASE_URL}/logs"
LOGOUT_URL = f"{BASE_URL}/logout"
INDEX_URL = f"{BASE_URL}/"

# --- User Credentials ---
# !!! IMPORTANT: Replace with your actual passwords !!!
TEST_USER_PREDICTOR = "predictor01"
TEST_PASSWORD_PREDICTOR = "PredictPass123" # Replace with actual predictor password

TEST_USER_ADMIN = "myztprojectsender@gmail.com" # Or myztprojectsender@gmail.com if that's username
TEST_PASSWORD_ADMIN = "shahmir" # Replace with actual admin password

# --- Test Data Paths ---
DATA_DIR = 'data'
X_TEST_CLEAN_PATH = os.path.join(DATA_DIR, 'x_test.npy')
X_TEST_ADV_PATH = os.path.join(DATA_DIR, 'x_test_adv.npy')
Y_TEST_PATH = os.path.join(DATA_DIR, 'y_test_categorical.npy') # Need labels for accuracy check

# --- Test Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Fixtures (pytest setup/teardown) ---
@pytest.fixture(scope="module")
def session():
    """Creates a requests session for the test module."""
    # Check if server is running before tests start
    try:
         # Add verify=False if testing HTTPS and using self-signed cert
         requests.get(BASE_URL, timeout=3, verify=False)
         logging.info(f"Test Setup: Flask server appears running at {BASE_URL}")
    except requests.exceptions.ConnectionError:
         pytest.fail(f"Test Setup FAILED: Flask server not running at {BASE_URL}. Start 'python run.py'.")
    except requests.exceptions.Timeout:
         pytest.fail(f"Test Setup FAILED: Connection to Flask server timed out at {BASE_URL}.")
    # Return session object
    s = requests.Session()
    # Optional: Set default verify=False for the session if testing HTTPS
    # s.verify = False
    return s


@pytest.fixture(autouse=True)
def log_test_marker(request):
    """Fixture to write a marker line to the log file before each test."""
    marker = f"--- Starting Test: {request.node.name} ---"
    try:
        # Ensure log directory exists (might be created by app on startup, but good practice)
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            # Use datetime import correctly
            f.write(f"\n{datetime.now().isoformat()} | TEST_MARKER | {marker}\n")
    except IOError as e:
        logging.warning(f"Could not write test marker to log file {LOG_FILE}: {e}")
    yield # Test runs here


# --- Helper Functions ---
def login(session, username, password):
    """
    Logs in non-admin users or initiates MFA for admin.
    Returns True ONLY if immediate redirect to index happens (non-admin success).
    Returns False otherwise (fail or admin MFA step needed).
    """
    try:
        payload = {'username': username, 'password': password}
        # Add verify=False if testing HTTPS and using self-signed cert
        response = session.post(LOGIN_URL, data=payload, allow_redirects=False, verify=False)
        logging.info(f"Login attempt for '{username}': Status={response.status_code}, Location={response.headers.get('Location')}")

        # Check ONLY for successful redirect to index page (non-admin success)
        return response.status_code == 302 and urlparse(INDEX_URL).path == urlparse(response.headers.get('Location', '')).path
    except requests.exceptions.RequestException as e:
        logging.error(f"Login request failed for '{username}': {e}")
        return False

def logout(session):
     """Logs out using the provided requests session."""
     try:
         expected_login_path = urlparse(LOGIN_URL).path
         # Add verify=False if testing HTTPS and using self-signed cert
         response = session.get(LOGOUT_URL, allow_redirects=False, verify=False)
         logging.info(f"Logout attempt: Status={response.status_code}")
         actual_logout_redirect = response.headers.get('Location', '')
         return response.status_code == 302 and urlparse(actual_logout_redirect).path == expected_login_path
     except requests.exceptions.RequestException as e:
         logging.error(f"Logout request failed: {e}")
         return False

def check_log_contains(expected_key, expected_value, max_wait_sec=5, since_marker=None):
    """
    Checks if the log file contains a JSON entry with the specified key/value pair,
    optionally only checking after a specific marker line.
    """
    start_time = time.time()
    substring_found = False
    # Read log content once per check loop iteration
    log_content = ""
    try:
        with open(LOG_FILE, 'r') as f:
            log_content = f.read()
    except FileNotFoundError:
        logging.warning(f"Log Check: Log file {LOG_FILE} not found yet.")
        # Continue loop to allow file creation/flush
    except Exception as e:
        logging.error(f"Log Check Error reading log file: {e}")
        return False # Don't keep trying on error

    # Optional: If marker provided, only search after the last occurrence of the marker
    search_content = log_content
    if since_marker:
        last_marker_pos = log_content.rfind(since_marker)
        if last_marker_pos != -1:
            search_content = log_content[last_marker_pos:]
        else:
             logging.warning(f"Log check marker '{since_marker}' not found.") # Search whole log if marker missing

    while time.time() - start_time < max_wait_sec:
        found_in_current_read = False
        # Split into lines and parse JSON
        for line in search_content.splitlines():
            line = line.strip()
            if not line: continue
            try:
                log_entry = json.loads(line)
                if log_entry.get(expected_key) == expected_value:
                    logging.info(f"Log Check PASSED: Found '{expected_key}': '{expected_value}'")
                    found_in_current_read = True
                    substring_found = True
                    break # Found it in this line
            except json.JSONDecodeError:
                continue # Ignore non-json lines
        if found_in_current_read: break # Exit while loop if found

        # If not found, re-read the file in the next iteration (allows for flushing)
        if not substring_found:
            time.sleep(0.5) # Wait before retrying
            try:
                with open(LOG_FILE, 'r') as f:
                     log_content = f.read()
                search_content = log_content # Update content to search for next loop
                if since_marker: # Re-apply marker logic if needed
                    last_marker_pos = log_content.rfind(since_marker)
                    if last_marker_pos != -1: search_content = log_content[last_marker_pos:]
            except Exception: pass # Ignore re-read errors briefly


    if not substring_found:
         logging.error(f"Log Check FAILED: Did not find '\"{expected_key}\": \"{expected_value}\"' in relevant part of {LOG_FILE} within {max_wait_sec}s")
    return substring_found


# === Test Functions ===

def test_unauthorized_access_index(session, request):
    """Test accessing index page without login redirects to login."""
    print("\nRunning test: test_unauthorized_access_index")
    test_marker = f"--- Starting Test: {request.node.name} ---" # Get marker for log check
    # Add verify=False if testing HTTPS
    response = session.get(INDEX_URL, allow_redirects=False, verify=False)
    expected_login_path = urlparse(LOGIN_URL).path
    actual_redirect_location = response.headers.get('Location', '')

    assert response.status_code == 302, f"Expected redirect (302) but got {response.status_code}"
    assert urlparse(actual_redirect_location).path == expected_login_path, \
           f"FAIL: Did not redirect / to login path '{expected_login_path}'. Got: '{actual_redirect_location}'"
    # Check log for denial AFTER the marker for this test
    assert check_log_contains(expected_key='event_type', expected_value='authn_fail_nouser', since_marker=test_marker), \
           "Log verification failed for unauthorized index access"

def test_unauthorized_access_logs(session, request):
    """Test accessing logs page without login redirects to login."""
    print("\nRunning test: test_unauthorized_access_logs")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    # Add verify=False if testing HTTPS
    response = session.get(LOGS_URL, allow_redirects=False, verify=False)
    expected_login_path = urlparse(LOGIN_URL).path
    actual_redirect_location = response.headers.get('Location', '')

    assert response.status_code == 302, f"Expected redirect (302) but got {response.status_code}"
    assert urlparse(actual_redirect_location).path == expected_login_path, \
           f"FAIL: Did not redirect /logs to login path '{expected_login_path}'. Got: '{actual_redirect_location}'"
    # Check log for denial
    assert check_log_contains(expected_key='event_type', expected_value='authn_fail_nouser', since_marker=test_marker), \
           "Log verification failed for unauthorized logs access"

def test_invalid_login_password(session, request):
    """Test login with correct user but wrong password."""
    print("\nRunning test: test_invalid_login_password")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    assert not login(session, TEST_USER_ADMIN, "wrongpassword"), "Login succeeded with wrong password"
    # Check log for specific failure reason (ensure event_type is correct in routes.py)
    assert check_log_contains(expected_key='fail_reason', expected_value='invalid_credentials', since_marker=test_marker), \
           "Log verification failed for invalid password"

def test_invalid_login_user(session, request):
    """Test login with non-existent user."""
    print("\nRunning test: test_invalid_login_user")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    assert not login(session, "notauser", "anypassword"), "Login succeeded for non-existent user"
    # Check log for specific failure reason logged in auth.py verify_password
    assert check_log_contains(expected_key='reason', expected_value='user_not_found', since_marker=test_marker), \
           "Log verification failed for user not found"


def test_predictor_login_logout(session, request):
    """Test successful login and logout for predictor."""
    print("\nRunning test: test_predictor_login_logout")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    assert login(session, TEST_USER_PREDICTOR, TEST_PASSWORD_PREDICTOR), "Predictor login failed"
    assert check_log_contains(expected_key='event_type', expected_value='login_success', since_marker=test_marker), \
           "Log verification failed for predictor login"
    assert logout(session), "Predictor logout failed"
    assert check_log_contains(expected_key='event_type', expected_value='logout', since_marker=test_marker), \
           "Log verification failed for predictor logout"


def test_predictor_access_denied_logs(session, request):
    """Test predictor cannot access admin logs page."""
    print("\nRunning test: test_predictor_access_denied_logs")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    assert login(session, TEST_USER_PREDICTOR, TEST_PASSWORD_PREDICTOR), "Predictor login failed"
    # Add verify=False if testing HTTPS
    response = session.get(LOGS_URL, allow_redirects=False, verify=False)
    expected_index_path = urlparse(INDEX_URL).path
    actual_redirect_location = response.headers.get('Location', '')

    assert response.status_code == 302, f"Predictor access to /logs expected redirect (302), got {response.status_code}"
    assert urlparse(actual_redirect_location).path == expected_index_path, \
           f"FAIL: Predictor access to /logs did not redirect to index path '{expected_index_path}'. Redirected to: '{actual_redirect_location}'"
    # Check log for authorization failure
    assert check_log_contains(expected_key='event_type', expected_value='authz_fail_role', since_marker=test_marker), \
           "Log verification failed for predictor accessing logs"
    logout(session)


def test_admin_login_logout_manual(session, request):
    """Placeholder test acknowledging manual verification needed for admin MFA flow."""
    print("\nRunning test: test_admin_login_logout_manual")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    logging.warning("Admin login test needs manual verification via browser due to MFA email flow.")
    print("SKIPPING automated admin login/logout assertions. Verify manually.")
    # No assertions here, just serves as a reminder
    pass


def test_admin_access_logs_manual(session, request):
    """Placeholder test acknowledging manual verification needed for admin log access."""
    print("\nRunning test: test_admin_access_logs_manual")
    test_marker = f"--- Starting Test: {request.node.name} ---"
    logging.warning("Admin log access test needs manual verification via browser due to MFA email flow.")
    print("SKIPPING automated admin log access test. Verify manually after admin login.")
    # No assertions here
    pass

# === Add Prediction Tests Here (Manual Verification Recommended) ===
# def test_predictor_predict_clean(session): ...
# def test_predictor_predict_adversarial(session): ...