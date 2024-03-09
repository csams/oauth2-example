This is an example application that shows an [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) [authorization code flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) using a confidential client and
[PKCE](https://datatracker.ietf.org/doc/html/rfc7636) with [Keycloak](https://www.keycloak.org/).

[OAuth 2.0 and OpenID Connect (in plain English)](https://www.youtube.com/watch?v=996OiexHze0&ab_channel=OktaDev) from `OktaDev` is a great explainer of the OAuth2 authorization
code flow and how OIDC piggy backs on it.

The [Keycloak Using Quarkus playlist](https://youtube.com/playlist?list=PLHXvj3cRjbzsVyj6Pxfu4uRE1PtWa2CIw&feature=shared) by `Dive Into Development` does a great job walking through Keycloak configuration.

This project assumes you have a [Keycloak](https://www.keycloak.org/) instance running and a realm created.

Once everything is working, when you access `http://localhost:5000` the first time, you will be redirected to
Keycloak to login. After you login, you'll be redirected back to the app where you can view the `well-known`
configuration of Keycloak, view `oidc`, `access`, and `refresh` tokens, and make a request to a backend
service that requires an access token.

To configure your realm for the app, follow these instructions:

1. Create a client called `webrca` with client authentication enabled.
   1. Open the client options and create a `view` role for it.
2. Create a client called `rhdh` with client authentication enabled.
   1. Set the root and home URLs to `http://localhost:5000`.
   2. Set a valid redirect URI to `http://localhost:5000/callback`
3. In the advanced settings for the `rhdh` client, set Proof Key for Code Exchange to use `S256`.
4. Create a top level Client scope called `webrca:view` and add the `view` role from the `webrca` client to
   it.
5. Add the `webrca:view` client scope to the `rhdh` client in Clients -> rhdh -> Client scopes.
6. Create a user and add the `view` role from the `webrca` client to it.  Set a password for the user, turn
   temporary password off, disable any requirements to verify email, etc.
7. Create a `backstage.env` file similar to the example one in the repo root and fill in the values.  The
   authorization server is just the URL to your Keycloak instance.  The CLIENT_ID and CLIENT_SECRET are in the
   Settings and Credentials tabs of the client.
8. Likewise, create a `webrca.env` file like `webrca.example.env` and fill in the blanks.

Make a python virtual environment, enable it, and install the requirements:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the backend service like this:
```bash
flask -e webrca.env -A webrca run -p 6000 --debug
```

In a separate window start the frontend service like this:
```bash
flask -e backstage.env -A backstage run -p 5000 --debug
```

Browse to `http://localhost:5000`
