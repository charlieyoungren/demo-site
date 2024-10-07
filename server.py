from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    current_app,
    g,
    session,
    abort,
    send_file
)
from functools import wraps
from dotenv import load_dotenv

import logging
import os
from os import environ as env

from urllib.parse import urlencode, quote_plus
import json

from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.debug = True

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


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "profile" not in session:
            # Redirect to Login page here
            return redirect("/")
        return f(*args, **kwargs)  # do the normal behavior -- return as it does.

    return decorated


def render_page(template, **kwargs):
    return render_template(template, user=session.get("user"), **kwargs)

def render_error(kind, message):
    return render_template("error.html", kind=kind, message=message)

@app.errorhandler(500)
def internal_error(error):
    return render_error("500 Internal Server Error", error)

@app.errorhandler(404)
def not_found(error):
    return render_error("404 Not Found", "The page you requested was not found.")

@app.route("/")
def index_page():
    return render_page("hello.html")

@app.route("/main")
@requires_auth
def main_page():
    return render_page("main.html")

### AUTH ###
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["profile"] = token
    return redirect("/main")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index_page", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )
