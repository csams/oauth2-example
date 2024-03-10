# Overview
This is an example application that uses a confidential client in [Keycloak](https://www.keycloak.org/) to show the [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)
[authorization code flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) + [OIDC](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) with [PKCE](https://datatracker.ietf.org/doc/html/rfc7636e).  It has a service called `frontend` that is the
OAuth2 client, and a service called `backend` that is the resource server.

[OAuth 2.0 and OpenID Connect (in plain English)](https://www.youtube.com/watch?v=996OiexHze0&ab_channel=OktaDev) from `OktaDev` is a great explainer of the OAuth2
authorization code flow and how [OIDC](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) piggy backs on it.

The [Keycloak Using Quarkus playlist](https://youtube.com/playlist?list=PLHXvj3cRjbzsVyj6Pxfu4uRE1PtWa2CIw&feature=shared) by `Dive Into Development` does a great job walking through Keycloak
configuration.

# Starting the services
If you have `podman` installed, you can start a pre-configured Keycloak instance like this:
```bash
./scripts/start-keycloak.sh
```
The script starts KeyCloak in development mode with statically defined credentials and credentials baked into
an imported realm, so *DO NOT USE THIS SYSTEM FOR ANYTHING OTHER THAN LEARNING*.

KeyCloak will be listening at `http://localhost:8080` and will have imported the realm `MyRealm` along with
some test users from `./realm-data`.  The admin username is `admin`, and the admin password is `admin`.  There
are two users in `MyRealm`, `user1` and `user2`, that both have the password `password`.

Next, make a python virtual environment, enable it, and install the requirements:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Then, start the backend and frontend services in separate terminals:
```bash
./scripts/start-backend.sh
```
```bash
./scripts/start-frontend.sh
```
Now, when you access <http://localhost:5000> the first time, you will be redirected to Keycloak to login.  Use
`user1` / `password`, and you'll be redirected back to the app where you can view the `well-known` configuration
of Keycloak, see the `oidc`, `access`, and `refresh` tokens, and make a request to the backend service that
requires an access token.

# KeyCloak manual setup
If you'd rather configure a realm manually, follow these instructions.  Beware that on Keycloak pages with
tables (client scopes, roles, etc.), it's not obvious when more data exists than what's shown, so you may need
to adjust the table settings to show more than ten rows at a time.

1. In your realm settings, enable User Managed Access.
2. Create an OpenID Connect client called `backend` with client authentication enabled.
   1. Open the client and create a `view` role for it.
3. Create an OpenID Connect client called `frontend` with client authentication enabled.
   1. Set its root and home URLs to `http://localhost:5000`.
   2. Set a valid redirect URI to `http://localhost:5000/callback`
   3. In its advanced settings, set Proof Key for Code Exchange to `S256`.
4. In Client scopes create a realm level client scope called `backend:view`.
   1. Navigate to its "Scopes" tab and add the `view` role from the `backend` client to it.
   2. After clicking "Assign role" beware that you will need to select "Filter by clients" instead of "Filter
      by realm roles".  If you don't see the role, change the table settings to show more than ten entries by
      clicking the little arrow by "1-10".
5. Add the `backend:view` client scope to the `frontend` client in Clients -> frontend -> Client scopes.
6. Create a user
   1. Don't select any required actions
   2. Say the email is already verified
   2. Under Credentials set a password and turn temporary password off
   3. Under Role mapping add the `view` role from the `backend` client
      1. Again, you will have to change the filter from "Filter by Realm roles" to "Filter by clients" and may
         need to adjust the number of rows the table shows.
7. Update `data.json` in the root of the repo so one of the users matches the user you just created.
8. Update `frontend.env` in the repo root with your Keycloak instance's values. The authorization server is
   just the base URL to your Keycloak instance.  The CLIENT_ID and CLIENT_SECRET are in the Settings and
   Credentials tabs of the client.
9. Likewise, update `backend.env`.
