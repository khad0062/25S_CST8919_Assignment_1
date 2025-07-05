"""Python Flask WebApp Auth0 integration example
"""

import json
import logging
from datetime import datetime
from functools import wraps
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Create a decorator for authentication required routes
def requires_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            # Log unauthorized access attempt
            app.logger.warning(f"Unauthorized access attempt to {request.endpoint} from IP: {request.remote_addr}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


# Controllers API
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    
    # Log successful login
    user_info = token.get('userinfo', {})
    user_id = user_info.get('sub', 'Unknown')
    email = user_info.get('email', 'Unknown')
    timestamp = datetime.now().isoformat()
    
    app.logger.info(f"User login successful - User ID: {user_id}, Email: {email}, Timestamp: {timestamp}, IP: {request.remote_addr}")
    
    return redirect("/")


@app.route("/login")
def login():
    # Log login attempt
    app.logger.info(f"Login attempt initiated from IP: {request.remote_addr}")
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


# Add error handling for authentication errors
@app.errorhandler(Exception)
def handle_auth_error(ex):
    app.logger.error(f"Authentication error: {str(ex)}, IP: {request.remote_addr}")
    return render_template("home.html", error_message="Authentication failed. Please try again."), 500


@app.route("/protected")
@requires_auth
def protected():
    user_info = session.get("user", {}).get('userinfo', {})
    user_id = user_info.get('sub', 'Unknown')
    email = user_info.get('email', 'Unknown')
    timestamp = datetime.now().isoformat()
    
    # Log access to protected route
    app.logger.info(f"Access to protected route - User ID: {user_id}, Email: {email}, Timestamp: {timestamp}, IP: {request.remote_addr}")
    
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
        protected_message="You have successfully accessed the protected route!"
    )


@app.route("/logout")
def logout():
    # Log logout attempt
    if 'user' in session:
        user_info = session.get("user", {}).get('userinfo', {})
        user_id = user_info.get('sub', 'Unknown')
        email = user_info.get('email', 'Unknown')
        timestamp = datetime.now().isoformat()
        app.logger.info(f"User logout - User ID: {user_id}, Email: {email}, Timestamp: {timestamp}, IP: {request.remote_addr}")
    
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
