# ZeroTrust_AI_Project/app/__init__.py
import os
import logging
from flask import Flask, g, session
import sys
from datetime import timedelta
from pythonjsonlogger import jsonlogger
from flask_mail import Mail

# Ensure the main project directory is in the path to import config and utils
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import (FLASK_SECRET_KEY, # <<< Remove ADMIN_OTP if not using static
                       MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USE_SSL,
                       MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER) # <<< Import Mail config
    from .utils import setup_logging
    from .auth import verify_token
except ImportError as e:
    print(f"Error importing from config/utils/auth in app/__init__.py: {e}")
    sys.exit(1)
    
# --- Initialize Mail Extension --- 
mail = Mail()
# --------------------------------

def create_app():
    """Creates and configures the Flask application instance."""
    # Configure logging FIRST
    setup_logging() # Sets up root logger
    logger = logging.getLogger(__name__) # Get logger for this module
    logger.info("Creating Flask application...")
    
    # --- Explicitly set template_folder ---
    # Calculate path relative to project root (one level up from app.root_path)
    template_dir = os.path.abspath(os.path.join(project_root, 'templates'))
    logger.info(f"Attempting to set explicit template folder: {template_dir}")

    app = Flask(__name__, instance_relative_config=True, template_folder=template_dir) # Enable instance folder if needed
    app.config.from_mapping(
        #defaults we can change these for testing or production
        SECRET_KEY=FLASK_SECRET_KEY, # Crucial for sessions
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=30)
    )
   
    app.config['MAIL_SERVER'] = MAIL_SERVER
    app.config['MAIL_PORT'] = int(MAIL_PORT) # Port needs to be integer
    app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
    app.config['MAIL_USE_SSL'] = MAIL_USE_SSL
    app.config['MAIL_USERNAME'] = MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
    app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
    app.config['MAIL_DEBUG'] = True # <<< Add this
    mail.init_app(app)
    logger.info("Flask-Mail initialized.")
    # Could also load more config from config.py or instance folder
    @app.before_request
    def make_session_permanent():
        # Tells Flask to use the PERMANENT_SESSION_LIFETIME configuration
        session.permanent = True
    # --- User Loading for Each Request ---
    # This function runs before every request to load user info if logged in
    @app.before_request
    def load_logged_in_user():
        user_token = session.get('user_token') # Get token stored in session
        g.user = None # Default to no user
        if user_token:
            # Verify token from session against our active token store
            user_info = verify_token(user_token)
            if user_info:
                g.user = user_info # Store user info in g for this request cycle
                logger.debug(f"User {g.user['user_id']} loaded from session token.")
            else:
                # Token in session is invalid/expired, clear session
                session.clear()
                logger.debug("Invalid/expired token found in session, cleared session.")


    # --- Register Routes ---
    # Import routes AFTER app is created and possibly configured
    with app.app_context():
        from . import routes

    logger.info("Flask application created successfully.")
    return app