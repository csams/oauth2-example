import json
import logging
import os
import urllib
from base64 import b64decode
from base64 import urlsafe_b64encode as b64encode
from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256
from pprint import pformat

import jwt
import requests
from flask import Flask, Response, redirect, render_template, request, session

auth_server = os.environ.get("AUTHORIZATION_SERVER")
realm = urllib.parse.quote(os.environ.get("REALM", "Red Hat"))
scope = urllib.parse.quote(os.environ.get("SCOPE", "profile roles openid"))

# all of the authorization server endpoints and configuration we'll need live here
well_known_endpoint = (
    f"{auth_server}/auth/realms/{realm}/.well-known/openid-configuration"
)

client_id = os.environ.get("CLIENT_ID", "frontend")
client_secret = os.environ.get("CLIENT_SECRET")

redirect_uri = "http://localhost:5000/callback"
backend_endpoint = "http://localhost:6000/api/incidents"

log = logging.getLogger(__name__)


def create_app():
    logging.basicConfig(level=logging.DEBUG)

    # all the info we'll need about the authorization server
    well_known = requests.get(well_known_endpoint).json()

    # used to verify JWT signatures
    signing_algos = well_known["id_token_signing_alg_values_supported"]
    jwks_client = jwt.PyJWKClient(well_known["jwks_uri"])

    def exchange_code_for_tokens(code):
        """
        Exchange an authorization code for a set of tokens (oidc, access and refresh). The `request_uri` is
        required and must be the same as send in the original request that delivered the code even though
        keycloak isn't redirecting a browser back anywhere.
        """
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": session["pkce-data"]["code_verifier"],
            "grant_type": "authorization_code",
        }
        return requests.post(well_known["token_endpoint"], params).json()

    def decode_and_validate_token(raw_token):
        """
        Decode a token into its header, payload, and signature.

        Raise an exception if the signature is invalid, the client_id isn't in the list of approved audiences,
        the token has expired, etc.
        """
        signing_key = jwks_client.get_signing_key_from_jwt(raw_token)

        return jwt.api_jwt.decode_complete(
            raw_token,
            key=signing_key.key,
            algorithms=signing_algos,
            audience=client_id,
        )

    def protected(func):
        """
        This is a decorator to ensure only users who have logged in can access certain endpoints
        """

        @wraps(func)
        def inner(*args, **kwargs):
            if "id-token" not in session:
                return redirect("/login")
            id_token = session["id-token"]

            # lazy.. don't bother with refresh token - just send the user around through the auth server and login
            # again.
            if not datetime.fromtimestamp(
                id_token["payload"]["exp"]
            ) > datetime.now() + timedelta(seconds=5):
                return redirect("/login")

            return func(*args, **kwargs)

        return inner

    app = Flask(__name__)

    # needed to generate session cookies sent back to the browser
    app.secret_key = "random string"

    @app.route("/login")
    def login():
        """
        Login starts here.  We redirect the user's browser to the authorization server and pass along some
        query parameters telling the auth server who we are (client_id), the response type we're looking for
        (we want a code we can exchange for an access token), the access we'd like so we can perform actions
        on behalf of the user (scopes), and where to redirect the user's browser after they've logged in
        (redirect_uri).  The state bit helps us tie the auth code request to the callback request.
        """
        state = b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        session.clear()
        session["state"] = state

        auth_endpoint = well_known["authorization_endpoint"]

        p = create_pkce()
        session["pkce-data"] = p
        code_challenge = p["code_challenge"]
        code_challenge_method = p["code_challenge_method"]

        r = urllib.parse.quote(redirect_uri)
        return redirect(
            f"{auth_endpoint}?response_type=code&client_id={client_id}&redirect_uri={r}&scope={scope}&state={state}&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}"
        )

    @app.route("/callback")
    def callback():
        """
        The authorization server will have redirected the user's browser back to here with parameters
        containing the authorization code.  We need to exchange it for an oidc token, access token, and
        refresh token.
        """
        args = request.args

        # is this the response to the request for an authorization code we made in this session?
        if args.get("state") != session.get("state"):
            log.error(f"State mismatch: {args.get('state')} != {session.get('state')}")
            return Response("<p>State mismatch</p>", 401)

        # get the auth code
        code = args.get("code")
        if code is None:
            # the callback request would include an error_description and some other data if the user failed
            # to login or decided not to grant the requested scopes.
            log.error(args)
            return Response("<p>Login failure</p>", 401)

        # exchange the auth code for the id and access tokens (there's also a refresh_token in here)
        tokens = exchange_code_for_tokens(code)
        if "error" in tokens:
            log.warn(tokens)
            return Response(tokens["error_description"])

        # store the base64 encoded access and refresh tokens in the session as-is.
        session["access-token"] = tokens["access_token"]
        session["refresh-token"] = tokens["refresh_token"]

        # the undecoded token is used as an id_token_hint during logout
        session["raw-id-token"] = tokens["id_token"]

        # decode the id_token.  it will contain 3 keys: header, payload, and signature.  The payload contains
        # all the user claims.
        session["id-token"] = decode_and_validate_token(tokens["id_token"])

        return redirect("/")

    @app.route("/")
    @protected
    def index():
        """
        A simple landing page.
        """
        return render_template(
            "index.html",
            user=session["id-token"]["payload"],
            config=pformat(well_known),
        )

    @app.route("/incidents")
    @protected
    def incidents():
        """
        When we want to talk to the backend, the user will have granted us the right to do so through an access
        token.  We pass it to the backend as a bearer token.
        """
        id_token = session["id-token"]["payload"]
        access_token = session["access-token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        events = requests.get(backend_endpoint, headers=headers).json()
        return render_template("incidents.html", incidents=events, user=id_token)

    @app.route("/view-tokens")
    @protected
    def view_tokens():
        """
        Inspect all the tokens
        """
        id_token = pformat(session["id-token"])
        access_token = pformat(unverified_decode(session["access-token"]))
        refresh_token = pformat(unverified_decode(session["refresh-token"]))
        return render_template(
            "tokens.html",
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    @app.route("/logout")
    def logout():
        """
        Tell keycloak directly (over a back channel, i.e. without redirecting the user to keycloak) to log out
        the user.  If logout is successful, clear our session data.

        https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
        says to pass the client_id and id_token_hint

        https://www.keycloak.org/docs/latest/securing_apps/index.html#logout

        https://www.keycloak.org/docs/latest/securing_apps/index.html#logout-endpoint
        says you have to include the client_secret and refresh_token when invoking over the back channel
        """
        if "raw-id-token" in session:
            params = {
                "client_id": client_id,
                "client_secret": client_secret,
                "id_token_hint": session["raw-id-token"],
                "refresh_token": session["refresh-token"],
            }
            r = requests.post(well_known["end_session_endpoint"], params)
            session.clear()

            # Keycloak returns a 204 (No Content) if the logout was successful
            if r.status_code < 200 or r.status_code > 299:
                log.warn(r.text)
                # we failed... send the user over to Keycloak itself to log out
                return redirect(well_known["end_session_endpoint"])

            if "id-token" in session:
                user = session["id-token"]["payload"]
                log.debug(f"Logging out: {user['preferred_username']}")

            redirect("/login")
        return redirect("/")

    return app


def unverified_decode(tok):
    """
    Decode a raw token without verifying its contents against its signature.
    """
    parts = tok.split(".")

    # b64decode requires proper padding but ignores any extra padding characteres.  Just adding a handful of
    # '=' characters to the end of a string ensures decoding works if it's not properly padded.
    return {
        "header": json.loads(b64decode(parts[0] + "===")),
        "payload": json.loads(b64decode(parts[1] + "===")),
        "signature": parts[2],
    }


def create_pkce():
    """
    The idea here is you prevent man in the middle attacks by giving the authorization server a piece of
    encrypted text in the request for an authorization code, and then you send the plain text of what you
    encrypted in the request for the id and access tokens.  The authorization server encrypts the plain text
    in the second call and compares it to the encrypted version you initially sent.  If they match, the auth
    server knows it's you and not some MITM.

    https://datatracker.ietf.org/doc/html/rfc7636#section-4

        NOTE: The code verifier SHOULD have enough entropy to make it impractical to guess the value.  It is
        RECOMMENDED that the output of a suitable random number generator be used to create a 32-octet
        sequence.  The octet sequence is then base64url-encoded to produce a 43-octet URL safe string to use
        as the code verifier.

        The client then creates a code challenge derived from the code verifier by using one of the following
        transformations on the code verifier:

        plain
            code_challenge = code_verifier

        S256
            code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    """
    # Keycloak doesn't like "=" padding on the ends of base64 encoded strings.

    # base64 encode a random 32 octet string into a 43 octet code_verifier
    code_verifier = b64encode(os.urandom(32)).rstrip(b"=")

    # base64 encode the S256 encoded code_verifier
    code_challenge = b64encode(sha256(code_verifier).digest()).rstrip(b"=")
    return {
        "code_verifier": code_verifier.decode("ascii"),
        "code_challenge": code_challenge.decode("ascii"),
        "code_challenge_method": "S256",
    }
