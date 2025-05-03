# ZeroTrust_AI_Project/app/__init__.py
import os
import logging
from flask import Flask, g, session
import sys
from datetime import timedelta
from pythonjsonlogger import jsonlogger

# Ensure the main project directory is in the path to import config and utils
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import FLASK_SECRET_KEY
    from .utils import setup_logging
    from config import LOG_FILE, LOG_LEVEL
    from .auth import verify_token # <<< Import verify_token
except ImportError as e:
    print(f"Error importing from config/utils/auth in app/__init__.py: {e}")
    sys.exit(1)

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
    # --- Add these debug lines ---
    logger.info(f"Flask App Root Path: {app.root_path}")
    logger.info(f"Flask Template Folder (set explicitly): {app.template_folder}")
        # -----------------------------
    app.config.from_mapping(
        #defaults we can change these for testing or production
        SECRET_KEY=FLASK_SECRET_KEY, # Crucial for sessions
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=30)
    )
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