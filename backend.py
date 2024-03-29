import json
import logging
import requests
import os
import urllib

from pprint import pprint

import jwt

from flask import Flask, request, Response, jsonify

auth_server = os.environ.get("AUTHORIZATION_SERVER").rstrip("/")
realm = urllib.parse.quote(os.environ.get("REALM", "MyRealm"))

well_known_endpoint = (
    f"{auth_server}/realms/{realm}/.well-known/openid-configuration"
)

client_id = os.environ.get("CLIENT_ID", "backend")
client_secret = os.environ.get("CLIENT_SECRET")


def create_app():
    logging.basicConfig(level=logging.DEBUG)

    well_known = requests.get(well_known_endpoint).json()
    signing_algos = well_known["id_token_signing_alg_values_supported"]
    jwks_client = jwt.PyJWKClient(well_known["jwks_uri"])

    with open("data.json") as f:
        database = json.load(f)

    def decode_and_validate_token(raw_token):
        signing_key = jwks_client.get_signing_key_from_jwt(raw_token)
        return jwt.api_jwt.decode_complete(
            raw_token,
            key=signing_key.key,
            algorithms=signing_algos,
            audience=client_id,
        )

    app = Flask(__name__)

    @app.route("/api/incidents")
    def incidents():
        try:
            bearer = request.headers.get("Authorization")
            access_token = decode_and_validate_token(bearer.split()[1])["payload"]
        except:
            return Response("Unauthorized", status=401)

        # Was this token intended for us?  The "roles" client scope will add all client_ids to aud for which
        # the user has at least one associated role.
        if client_id not in access_token["aud"]:
            return Response("Unauthorized", status=401)

        # The calling service requested a client scope that maps to a subset of the user's roles.  That subset
        # is stored in the access token.  The client scope -> role association is defined in Keycloak.
        user = access_token["preferred_username"]
        roles = set(access_token["resource_access"].get(client_id, {}).get("roles", []))

        # is "view" one of the roles the user has and that we've been authorized to exercise?
        if "view" not in roles:
            return Response(
                "User does not have the role required for this request", status=403
            )

        return jsonify(database.get(user))

    return app
