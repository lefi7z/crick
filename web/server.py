"""Python Flask WebApp Auth0 integration example
"""

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
import requests
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")


oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
        "audience": "foobar",
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
    return redirect("/")


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
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

@app.route("/api/<path:endpoint>", methods=['GET', 'POST'])
def api_call(endpoint):
    if endpoint.startswith('watson'):
        return "for watson sync only", 401

    user = session.get("user")
    if user is None:
        return "unauthorized", 401

    token = user['id_token']
    print(token)
    r = requests.get('http://localhost:8000/' + endpoint,
            headers={'Authorization': 'Bearer ' + str(token)})
    if r.ok:
        return r.json()
    return r.text, r.status_code


@app.route("/userinfo")
def get_user():
    user = session.get("user")
    if user is None:
        return "unauthorized", 401

    token = user['access_token']
    print(token)
    r = requests.get('https://lefitz.eu.auth0.com/userinfo',
            headers={'Authorization': 'Bearer ' + str(token)})
    return r.text


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
