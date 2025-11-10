"""
Vercel serverless function entry point for Flask application
"""
import sys
import os

# Set Vercel environment flag
os.environ['VERCEL'] = '1'

# Add the parent directory to the path so we can import app
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import the Flask app
from app import app, db

# Initialize database tables if they don't exist
# Note: In serverless, /tmp is ephemeral, so data won't persist between deployments
# For production, consider using Vercel Postgres or another database service
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Database initialization note: {e}")

# Export the app for Vercel
# Vercel Python runtime automatically handles WSGI applications
