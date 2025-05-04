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
import json
from flask_mail import Message # <<< Import Message
from app import mail # <<< Import the mail instance from __init__

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import project modules
from .auth import (verify_password, generate_token, verify_token,
                   check_permission, get_user_role, invalidate_token,generate_and_store_otp,verify_otp, MFA_OTP_EXPIRY_SECONDS)
from .utils import decrypt_data, load_keras_model_from_bytes
try:
    from config import LOG_FILE
except ImportError:
    LOG_FILE = 'activity.log' # Fallback

try:
    from config import LOG_FILE, ADMIN_OTP # <<< Add ADMIN_OTP
except ImportError:
    # ... (keep fallback for LOG_FILE) ...
    ADMIN_OTP = None # Set fallback for OTP
    print("Warning: Could not import ADMIN_OTP from config.")

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
                print(f"DEBUG: login_required detected g.user is None for path {request.path}")
                event_data['event_type'] = 'authn_fail_nouser'
                logger.warning("Access denied: User not logged in.", extra=event_data)
                flash('Please log in to access this page.', 'error')
                
                return redirect(url_for('login'))

            current_user_role = g.user['role']
            current_user_id = g.user['user_id']
            event_data.update({'user_id': current_user_id, 'role': current_user_role})
            logger.debug("Session check passed", extra={**event_data, 'event_type':'authn_session_success'})

            if required_role:
                if not check_permission(required_role, current_user_role):
                    event_data['event_type'] = 'authz_fail_role' # OK
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
    logger.debug("Rendering index page", extra={'user_id': g.user['user_id'], 'role': g.user['role'], 'event_type': 'render_index'}) # Added
    return render_template('index.html', prediction=None)

@app.route('/login', methods=['GET', 'POST'])

def login():
    """Handles Step 1: Username/Password verification. Sends OTP email for admins."""
    # If user is already logged in via a valid session, redirect them
    if g.user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # OTP is NOT submitted on this initial form anymore
        error = None
        event_data = {'username_attempted': username, 'event_type': 'login_step1_attempt'}
        logger.info("Processing login step 1 (Password)", extra=event_data)

        if not username or not password:
            error = 'Username and password required.'
            event_data['fail_reason'] = 'missing_credentials'
            logger.warning("Login Step 1 failed", extra=event_data)
        # --- Step 1: Verify Password ---
        elif not verify_password(username, password):
            error = 'Invalid username or password.'
            event_data['fail_reason'] = 'invalid_credentials'
            # verify_password logs internally, log overall failure here
            logger.warning("Login Step 1 failed", extra=event_data)
        else:
            # --- Password Correct ---
            user_role = get_user_role(username)
            event_data['role'] = user_role

            if user_role == 'admin':
                # --- Admin Needs MFA Step 2: Generate & Email OTP ---
                otp = generate_and_store_otp(username) # Generate/store OTP
                if otp:
                    # --- Attempt to Send Email ---
                    try:
                        admin_email = username # Assuming username is the email
                        if not admin_email or '@' not in admin_email: # Basic validation
                             raise ValueError("Admin username is not a valid email format for sending OTP.")

                        msg_subject = "Your Zero Trust AI Login OTP"
                        msg_body = f"Your One-Time Password for Zero Trust AI is: {otp}\n\nIt will expire in {MFA_OTP_EXPIRY_SECONDS // 60} minutes."
                        msg = Message(subject=msg_subject, recipients=[admin_email], body=msg_body)

                        mail.send(msg) # Send the email using Flask-Mail

                        event_data['recipient'] = admin_email
                        logger.info("MFA OTP email sent successfully.", extra={**event_data, 'event_type': 'mfa_email_sent'})
                        # --- Render the MFA verification page ---
                        # User needs to check their email and enter the code on this page
                        return render_template('mfa_verify.html', username=username) # Pass username to keep track

                    except Exception as e:
                        # Handle email sending failure
                        error = "MFA Error: Could not send OTP code via email. Please check server configuration or contact support."
                        event_data['fail_reason'] = 'mfa_email_fail'
                        event_data['error'] = str(e)
                        logger.error(f"Failed to send MFA email", extra=event_data, exc_info=True)
                        # Don't proceed to MFA page if email failed
                else:
                    # Handle OTP generation failure
                    error = "MFA Error: Could not initiate MFA process."
                    event_data['fail_reason'] = 'mfa_otp_gen_fail'
                    logger.error("Failed to generate OTP for admin.", extra=event_data)
            else:
                # --- Non-Admin Login Success (No MFA Needed) ---
                token = generate_token(username) # Regular token generation
                if not token:
                    error = 'Internal server error during login.'
                    event_data['fail_reason'] = 'token_gen_fail_non_admin'
                    logger.error("Login failed: Token generation failure", extra=event_data)
                else:
                    session.clear()
                    session['user_token'] = token
                    logger.info("Login successful (non-admin)", extra={'user_id': username, 'role': user_role, 'event_type': 'login_success'})
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))

        # --- If any error occurred during POST processing ---
        if error:
             flash(error, 'error')
             # Log general failure if not specifically logged above
             if 'fail_reason' not in event_data: event_data['fail_reason'] = 'unknown_step1_fail'
             logger.warning("Login Step 1 form processing failed overall", extra={**event_data, 'error_msg': error, 'event_type': 'login_step1_form_fail'})


    # --- Render login page on GET or if POST had errors ---
    logger.debug("Rendering login page", extra={'event_type': 'render_login_page'})
    return render_template('login.html')


# --- Keep the /verify-mfa route exactly as it was before ---
# It handles the submission from mfa_verify.html
@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Handles Step 2: MFA OTP Verification from form submission."""
    if g.user: return redirect(url_for('index')) # Should not happen if logout occurs on failure

    username = request.form.get('username')
    otp_attempt = request.form.get('otp')
    event_data = {'username_attempted': username, 'event_type': 'login_step2_mfa_attempt'}
    logger.info("Processing MFA Step 2 (OTP Verification)", extra=event_data)

    if not username or not otp_attempt:
        flash("MFA Error: Missing username or OTP code.", 'error')
        event_data['fail_reason'] = 'missing_mfa_data'
        logger.warning("MFA verification failed", extra=event_data)
        return redirect(url_for('login')) # Go back to start

    # --- Verify the OTP using the function from auth.py ---
    if verify_otp(username, otp_attempt): # verify_otp logs internally
        # --- MFA Correct ---
        user_role = get_user_role(username) # Should be 'admin'
        token = generate_token(username) # Logs internally
        if not token:
            flash('MFA Error: Internal server error after MFA.', 'error')
            event_data['fail_reason'] = 'mfa_token_gen_fail'
            logger.error("Token generation failed after successful MFA.", extra=event_data)
            return redirect(url_for('login'))
        else:
            session.clear()
            session['user_token'] = token
            logger.info("MFA Login successful", extra={'user_id': username, 'role': user_role, 'event_type': 'login_success_mfa'})
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
    else:
        # --- MFA Incorrect or Expired ---
        flash('Invalid or expired One-Time Password. Please try logging in again.', 'error')
        # verify_otp logs failure reason internally
        logger.warning("MFA verification failed.", extra=event_data)
        # Redirect back to the main login page to restart the whole process
        return redirect(url_for('login'))

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
    """Displays log analysis summary, charts, and raw log content."""
    user_id = g.user['user_id']
    event_data = {'user_id': user_id, 'role': g.user['role'], 'event_type': 'log_view_request'}
    logger.info("Log view request", extra=event_data)
    log_content = ""
    analysis_summary = None
    log_read_error = None
    chart_data = {} # <<< Initialize dict for chart data

    try:
        # Perform log analysis
        analysis_summary = get_log_summary(log_path=LOG_FILE, time_window_minutes=60)

        # --- Prepare data for Chart.js --- <<< ADD THIS BLOCK <<<
        if analysis_summary and analysis_summary.get('event_counts'):
            # Sort by count descending for better chart display
            sorted_events = sorted(analysis_summary['event_counts'].items(), key=lambda item: item[1], reverse=True)
            chart_data['eventCounts'] = {
                'labels': [item[0] for item in sorted_events],
                'data': [item[1] for item in sorted_events]
            }

        if analysis_summary and analysis_summary.get('prediction_outcomes'):
             # Sort outcomes (optional, might want specific order)
             sorted_predictions = sorted(analysis_summary['prediction_outcomes'].items(), key=lambda item: item[0])
             chart_data['predictionOutcomes'] = {
                 'labels': [item[0] for item in sorted_predictions],
                 'data': [item[1] for item in sorted_predictions]
             }
        # Add more chart data preparation here if needed (e.g., failed logins)
        # ------------------------------------

        # Read raw log content (limit lines)
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            log_content = "".join(lines[-100:]) # Last 100 lines

    except FileNotFoundError:
        log_read_error = f"Log file not found at {LOG_FILE}"
        event_data['event_type'] = 'log_view_fail' # OK
        event_data['error'] = 'FileNotFound'
        logger.error(log_read_error, extra=event_data)
        flash(log_read_error, 'error')
        if analysis_summary and not analysis_summary.get('errors'):
            analysis_summary['errors'] = [log_read_error]
    except Exception as e:
        log_read_error = f"Error reading log file or preparing chart data: {e}"
        event_data['event_type'] = 'log_view_fail' # OK
        event_data['error'] = str(e)
        logger.error(f"Error reading log file for admin view", extra=event_data, exc_info=True) # OK
        flash('Error reading log file or preparing analysis.', 'error')
        if analysis_summary and not analysis_summary.get('errors'):
            analysis_summary['errors'] = [log_read_error]

    # Render template, passing analysis, logs, and chart data (as JSON string)
    return render_template('logs.html',
                           analysis=analysis_summary,
                           log_content=log_content,
                           log_file_path=LOG_FILE,
                           # Safely embed chart data as JSON into the HTML/JS
                           chart_data_json=json.dumps(chart_data) # <<< Pass chart data as JSON
                          )

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