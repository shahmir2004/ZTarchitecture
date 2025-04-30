# ZeroTrust_AI_Project/app/routes.py

import logging
# Flask imports for rendering templates, redirects, sessions etc.
from flask import (request, jsonify, current_app as app, Response,
                   render_template, redirect, url_for, flash, session, g)
from functools import wraps # For creating decorators
import os
import sys
import io
from PIL import Image # For image processing
import numpy as np # For array manipulation

# Ensure the main project directory is in the path to import other modules
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import authentication functions and RBAC check
from .auth import (verify_password, generate_token, verify_token,
                   check_permission, get_user_role, invalidate_token)

# Import model loading and decryption utilities
from .utils import decrypt_data, load_keras_model_from_bytes

# Import config variables (optional, only if directly needed like LOG_FILE)
try:
    from config import LOG_FILE
except ImportError:
    print("Warning: Cannot import LOG_FILE from config in routes.py. Using default.")
    LOG_FILE = 'activity.log' # Fallback

logger = logging.getLogger(__name__) # Get logger for this module

# --- Global variable for model cache ---
loaded_model = None

def get_model():
    """Loads the model if not already cached. Includes ZT principle of decrypting on demand."""
    global loaded_model
    if loaded_model is None:
        logger.info("Model not cached. Attempting to load and decrypt...")
        decrypted_bytes = decrypt_data()
        if decrypted_bytes:
            loaded_model = load_keras_model_from_bytes(decrypted_bytes)
            if loaded_model:
                logger.info("Defended model loaded and cached successfully.")
            else:
                logger.error("Failed to load model from decrypted data.")
                loaded_model = None # Reset cache on failure
        else:
            logger.error("Failed to decrypt model data.")
            loaded_model = None
    return loaded_model

# --- Zero Trust Decorator (for Web UI Sessions) ---
def login_required(required_role=None):
    """Decorator to ensure user is logged in via session and checks role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # g.user is loaded by the @app.before_request function in __init__.py
            if g.user is None:
                logger.warning(f"Access denied to {request.path}. User not logged in.")
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login')) # Redirect to login page

            current_user_role = g.user['role']
            logger.debug(f"Session check: User '{g.user['user_id']}' (Role: {current_user_role}) accessing {request.path}")

            # --- RBAC Check (Least Privilege) ---
            if required_role:
                if not check_permission(required_role, current_user_role):
                    logger.warning(f"Permission denied for user '{g.user['user_id']}' (Role: {current_user_role}). Required role: '{required_role}' for {request.path}")
                    flash(f'Your role ({current_user_role}) does not have permission to access this page.', 'error')
                    # Redirect to index page, as they are logged in but lack permissions
                    return redirect(url_for('index'))

            # User is logged in and has necessary role (or no role specified)
            return f(*args, **kwargs) # Proceed to original function
        return decorated_function
    return decorator


# === Web Page Routes ===

@app.route('/')
@login_required() # Require login to see the main page
def index():
    """Renders the main application page (index.html)."""
    # No specific prediction data initially when just viewing the page
    return render_template('index.html', prediction=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    # If user already logged in (valid session found by before_request), redirect
    if g.user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        error = None
        logger.info(f"Login attempt for username: '{username}'")

        if not username or not password:
            error = 'Username and password required.'
            logger.warning("Login failed: Missing username or password in form")
        # Verify Explicitly (using auth.py function)
        elif not verify_password(username, password):
            error = 'Invalid username or password.'
            logger.warning(f"Login failed: Invalid credentials for username '{username}'")
        else:
            # --- Login Success ---
            # 1. Generate a token (UUID) and store it server-side (in ACTIVE_TOKENS dict)
            token = generate_token(username)
            if not token:
                 error = 'Internal server error during login.'
                 logger.error(f"Failed to generate token for user '{username}'")
            else:
                 # 2. Store the server-side token identifier in the user's secure browser session cookie
                 session.clear() # Ensure clean session
                 session['user_token'] = token # Flask handles secure cookie storage
                 # g.user will be set by before_request on the *next* request
                 logger.info(f"Login successful for user '{username}'. Token stored in session.")
                 flash('Login successful!', 'success')
                 return redirect(url_for('index')) # Redirect to main page

        # If error occurred during POST
        flash(error, 'error')

    # If GET request or login failed, render the login form
    return render_template('login.html')

@app.route('/logout')
@login_required() # Ensure user is logged in before logging out
def logout():
    """Logs the user out by clearing the session and invalidating the server-side token."""
    user_token = session.get('user_token')
    user_id = g.user['user_id'] if g.user else 'unknown' # Get user ID for logging before clearing

    if user_token:
        invalidate_token(user_token) # Remove token from our active server store

    session.clear() # Clear the browser session cookie
    g.user = None # Clear g.user for this request immediate context

    flash('You have been logged out.', 'success')
    logger.info(f"User '{user_id}' logged out (session cleared, server token invalidated).")
    return redirect(url_for('login')) # Redirect to login page

# --- Prediction Route (Handles Web Form Image Upload) ---
@app.route('/predict', methods=['POST'])
@login_required(required_role='predictor') # Checks session and role ('admin' implicitly allowed via check_permission)
def predict_image():
    """Handles image upload from web form, prediction, and renders result on index page."""
    user_id = g.user['user_id'] # Get user from session context (g)
    logger.info(f"Prediction request via web form from user '{user_id}'")
    prediction_result_data = None # Initialize

    # --- Check File Input ---
    if 'imagefile' not in request.files:
        flash('No image file part in the request.', 'error')
        logger.warning("Prediction failed: 'imagefile' not in request.files")
        return redirect(url_for('index'))

    file = request.files['imagefile']
    if file.filename == '':
        flash('No image selected for uploading.', 'error')
        logger.warning("Prediction failed: No file selected.")
        return redirect(url_for('index'))

    if file: # Basic check if file exists
        try:
            # --- 1. Process Image using Pillow ---
            img = Image.open(file.stream).convert('L') # Open image using file stream, convert to grayscale
            img = img.resize((28, 28)) # Resize to MNIST dimensions (28x28)
            # Convert image to numpy array, normalize to [0, 1]
            img_array = np.array(img).astype('float32') / 255.0
            # Reshape for model: (batch_size, height, width, channels)
            img_array = img_array.reshape(1, 28, 28, 1)
            logger.debug(f"Image processed successfully. Shape for model: {img_array.shape}")

            # --- 2. Load Model (using cached/decrypted version) ---
            model = get_model()
            if model is None:
                 logger.critical("Prediction failed: Model could not be loaded or is unavailable.")
                 flash('Model service temporarily unavailable. Please try again later.', 'error')
                 return redirect(url_for('index')) # Redirect on critical failure

            # --- 3. Make Prediction ---
            prediction_probs = model.predict(img_array)
            predicted_class = int(np.argmax(prediction_probs, axis=1)[0])
            confidence = float(np.max(prediction_probs))
            logger.info(f"Prediction by model successful: Class={predicted_class}, Confidence={confidence:.4f}")

            # Prepare results to pass back to the template
            prediction_result_data = {
                'predicted_class': predicted_class,
                'confidence': confidence
                # Optional: Could save the uploaded file temporarily and pass filename
                # 'image_filename': secure_filename(file.filename) # Need import secure_filename from werkzeug
            }

        except Exception as e:
            logger.error(f"Error during prediction processing for user '{user_id}': {e}", exc_info=True)
            flash('An error occurred during image processing or prediction.', 'error')
            # Don't redirect here, render index template showing the error context implicitly
            # The 'prediction' variable will be None in the template

    # --- 4. Render Result on Index Page ---
    # Re-render the index page, passing the prediction data (or None if error occurred)
    return render_template('index.html', prediction=prediction_result_data)

# --- Log Viewing Route ---
@app.route('/logs')
@login_required(required_role='admin') # Require admin role
def view_logs():
    """Displays the activity log content to admin users."""
    user_id = g.user['user_id']
    logger.info(f"Log view request from admin user '{user_id}'")
    try:
        with open(LOG_FILE, 'r') as f:
            # Read lines for potentially better handling of large files later
            log_content = f.read()
        # Render a simple template to display logs
        # Create templates/logs.html or display directly
        return Response(f"<pre>{log_content}</pre>", mimetype='text/html')
    except FileNotFoundError:
        logger.error(f"Admin log view failed: Log file not found at {LOG_FILE}")
        flash('Log file not found.', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error reading log file for admin view: {e}", exc_info=True)
        flash('Error reading log file.', 'error')
        return redirect(url_for('index'))


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