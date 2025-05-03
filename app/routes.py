# ZeroTrust_AI_Project/app/routes.py
import logging
from flask import (request, jsonify, current_app as app, Response,
                   render_template, redirect, url_for, flash, session, g)
from functools import wraps
import os
import sys
import io
from PIL import Image
import numpy as np
from analyze_logs import get_log_summary

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import project modules
from .auth import (verify_password, generate_token, verify_token,
                   check_permission, get_user_role, invalidate_token)
from .utils import decrypt_data, load_keras_model_from_bytes
try:
    from config import LOG_FILE
except ImportError:
    LOG_FILE = 'activity.log' # Fallback

logger = logging.getLogger(__name__) # Get logger for this module

# --- Global variable for model cache ---
loaded_model = None

def get_model():
    """Loads the model if not already cached."""
    global loaded_model
    # Use existing logging within decrypt_data and load_keras_model_from_bytes
    if loaded_model is None:
        decrypted_bytes = decrypt_data()
        if decrypted_bytes:
            loaded_model = load_keras_model_from_bytes(decrypted_bytes)
    return loaded_model

# --- Zero Trust Decorator (for Web UI Sessions) ---
def login_required(required_role=None):
    """Decorator to ensure user is logged in via session and checks role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            event_data = {'path': request.path, 'required_role': required_role}
            if g.user is None:
                event_data['event_type'] = 'authn_fail_nouser'
                logger.warning("Access denied: User not logged in.", extra=event_data)
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))

            current_user_role = g.user['role']
            current_user_id = g.user['user_id']
            event_data.update({'user_id': current_user_id, 'role': current_user_role})
            logger.debug("Session check passed", extra=event_data)

            if required_role:
                if not check_permission(required_role, current_user_role):
                    event_data['event_type'] = 'authz_fail_role'
                    logger.warning(f"Permission denied", extra=event_data)
                    flash(f'Your role ({current_user_role}) does not have permission to access this page.', 'error')
                    return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# === Web Page Routes ===

@app.route('/')
@login_required()
def index():
    """Renders the main application page (index.html)."""
    # Logging done by decorator and before_request handler
    return render_template('index.html', prediction=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if g.user: return redirect(url_for('index')) # Already logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        error = None
        event_data = {'username_attempted': username, 'event_type': 'login_attempt'}
        logger.info("Login attempt received", extra=event_data)

        if not username or not password:
            error = 'Username and password required.'
            event_data['fail_reason'] = 'missing_credentials'
            logger.warning("Login failed", extra=event_data)
        elif not verify_password(username, password):
            error = 'Invalid username or password.'
            event_data['fail_reason'] = 'invalid_credentials'
            # Note: verify_password already logs details
            logger.warning("Login failed", extra=event_data)
        else:
            token = generate_token(username) # Logs internally
            if not token:
                 error = 'Internal server error during login.'
                 event_data['fail_reason'] = 'token_gen_fail'
                 logger.error("Login failed", extra=event_data)
            else:
                 session.clear()
                 session['user_token'] = token
                 event_data['event_type'] = 'login_success'
                 # Don't log token itself
                 logger.info("Login successful, session created", extra={'user_id': username, 'event_type': 'login_success'})
                 flash('Login successful!', 'success')
                 return redirect(url_for('index'))

        flash(error, 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required()
def logout():
    """Logs the user out."""
    user_token = session.get('user_token')
    user_id = g.user['user_id'] if g.user else 'unknown'
    event_data = {'user_id': user_id, 'event_type': 'logout'}

    if user_token:
        invalidate_token(user_token) # Logs internally

    session.clear()
    g.user = None

    flash('You have been logged out.', 'success')
    logger.info("User logged out", extra=event_data)
    return redirect(url_for('login'))

# --- Prediction Route ---
@app.route('/predict', methods=['POST'])
@login_required(required_role='predictor')
def predict_image():
    """Handles image upload, prediction, and renders result on index page."""
    user_id = g.user['user_id']
    event_data = {'user_id': user_id, 'role': g.user['role'], 'event_type': 'predict_request'}
    logger.info("Prediction request received", extra=event_data)
    prediction_result_data = None

    if 'imagefile' not in request.files:
        flash('No image file part in the request.', 'error')
        event_data['fail_reason'] = 'no_file_part'
        logger.warning("Prediction failed", extra=event_data)
        return redirect(url_for('index'))

    file = request.files['imagefile']
    if file.filename == '':
        flash('No image selected for uploading.', 'error')
        event_data['fail_reason'] = 'no_file_selected'
        logger.warning("Prediction failed", extra=event_data)
        return redirect(url_for('index'))

    if file:
        try:
            img = Image.open(file.stream).convert('L')
            img = img.resize((28, 28))
            img_array = np.array(img).astype('float32') / 255.0
            img_array = img_array.reshape(1, 28, 28, 1)
            event_data['input_shape'] = img_array.shape
            logger.debug("Image processed successfully", extra=event_data)

            model = get_model()
            if model is None:
                 logger.critical("Prediction failed: Model could not be loaded.", extra=event_data)
                 flash('Model service temporarily unavailable.', 'error')
                 return redirect(url_for('index'))

            prediction_probs = model.predict(img_array)
            predicted_class = int(np.argmax(prediction_probs, axis=1)[0])
            confidence = float(np.max(prediction_probs))
            event_data.update({
                'predicted_class': predicted_class,
                'confidence': round(confidence, 4),
                'event_type': 'predict_success'
            })
            logger.info("Prediction successful", extra=event_data)

            prediction_result_data = {'predicted_class': predicted_class, 'confidence': confidence}

        except Exception as e:
            event_data['event_type'] = 'predict_fail'
            event_data['error'] = str(e)
            logger.error("Error during prediction processing", extra=event_data, exc_info=True)
            flash('An error occurred during prediction.', 'error')
            # Render index, prediction will be None
            return render_template('index.html', prediction=None)

    return render_template('index.html', prediction=prediction_result_data)


# --- Log Viewing Route ---
@app.route('/logs')
@login_required(required_role='admin')
def view_logs():
    """Displays log analysis summary and raw log content to admin users."""
    user_id = g.user['user_id']
    event_data = {'user_id': user_id, 'role': g.user['role'], 'event_type': 'log_view_request'}
    logger.info("Log view request", extra=event_data)
    log_content = ""
    analysis_summary = None
    log_read_error = None

    try:
        # Perform log analysis (e.g., last 60 minutes)
        analysis_summary = get_log_summary(log_path=LOG_FILE, time_window_minutes=60)

        # Read raw log content (potentially limit lines for display)
        with open(LOG_FILE, 'r') as f:
            # Example: Read last 100 lines - adjust as needed
            lines = f.readlines()
            log_content = "".join(lines[-100:]) # Get last 100 lines
            # Or simply: log_content = f.read() # If file is small

    except FileNotFoundError:
        log_read_error = f"Log file not found at {LOG_FILE}"
        logger.error(log_read_error, extra=event_data)
        flash(log_read_error, 'error')
        # analysis_summary might still have the error message from get_log_summary
        if analysis_summary and not analysis_summary.get('errors'):
             analysis_summary['errors'] = [log_read_error] # Ensure error is reflected
    except Exception as e:
        log_read_error = f"Error reading log file: {e}"
        logger.error(log_read_error, extra=event_data, exc_info=True)
        flash('Error reading log file.', 'error')
        if analysis_summary and not analysis_summary.get('errors'):
             analysis_summary['errors'] = [log_read_error]

    # Render the template, passing summary, raw content, and file path
    return render_template('logs.html',
                           analysis=analysis_summary,
                           log_content=log_content,
                           log_file_path=LOG_FILE)

# === Commented out API Endpoints ===
# ... (keep them commented out or remove) ...

# === Original API Endpoints (Commented Out/Optional) ===
# If you need programmatic API access alongside the web UI,
# re-enable these, potentially under an /api/ prefix,
# and decide on authentication (session cookie if called from browser JS,
# or header tokens/API keys if called from external scripts).

# @app.route('/api/predict', methods=['POST'])
# @token_required(required_role='predictor') # Use header token decorator
# def api_predict(current_user):
#     # Logic similar to web predict, but expects/returns JSON
#     pass

# @app.route('/api/get_logs', methods=['GET'])
# @token_required(required_role='admin') # Use header token decorator
# def api_get_logs(current_user):
#     # Logic similar to web log view, but returns JSON or plain text
#     pass

# @app.route('/api/logout', methods=['POST'])
# @token_required()
# def api_logout(current_user):
#     # Logic using header token invalidation
#     pass