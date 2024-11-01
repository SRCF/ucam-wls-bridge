from datetime import datetime, timedelta, timezone
import os
from typing import Dict, Optional, Type, Union
from urllib.parse import parse_qs, urlsplit

from flask import Flask, make_response, redirect, request, session, url_for

from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import FlaskOAuth2App, OAuth

from ucam_wls import AuthPrincipal, AuthRequest, load_private_key, LoginService
from ucam_wls.errors import NoMutualAuthType, ProtocolVersionUnsupported, WLSError
from ucam_wls.status import AUTH_DECLINED, NO_MUTUAL_AUTH_TYPES, REQUEST_PARAM_ERROR, UNSUPPORTED_PROTO_VER


app = Flask(__name__)
app.secret_key = os.environ["UWB_SECRET_KEY"]
app.config.update({
    "UPSTREAM_CLIENT_ID": os.environ["UWB_OIDC_CLIENT_ID"],
    "UPSTREAM_CLIENT_SECRET": os.environ["UWB_OIDC_CLIENT_SECRET"],
})

oauth = OAuth(app)
oauth.register("upstream", server_metadata_url=os.environ["UWB_OIDC_URL"], client_kwargs={"scope": "openid profile"})
upstream: FlaskOAuth2App = oauth.upstream

wls = LoginService(load_private_key(os.environ["UWB_KEY_FILE"], int(os.environ["UWB_KEY_ID"])), ["pwd"])

OIDC_EMAIL_DOMAIN = os.environ.get("UWB_OIDC_EMAIL_DOMAIN")

WLS_ERROR_MAP: Dict[Type[WLSError], int] = {
    NoMutualAuthType: NO_MUTUAL_AUTH_TYPES,
    ProtocolVersionUnsupported: UNSUPPORTED_PROTO_VER,
}


class WLSFail(Exception):
    pass


SESSION_KEY = "uwb_auth"

def get_user() -> Optional[str]:
    return session.get(SESSION_KEY)

def set_user(user: Optional[str]):
    session[SESSION_KEY] = user


def parse_wls(query: str):
    try:
        req = AuthRequest.from_query_string(query)
    except WLSError as e:
        raise WLSFail(None, e)
    if not wls.have_mutual_auth_type(req):
        raise WLSFail(req, NoMutualAuthType())
    parts = urlsplit(req.url)
    if not parts.netloc:
        raise WLSFail(req, "No return domain specified.", REQUEST_PARAM_ERROR)
    if parts.scheme != "https" and parts.netloc != "localhost":
        raise WLSFail(req, "Insecure web application.", REQUEST_PARAM_ERROR)
    return req


def fail(req: Optional[AuthRequest], error: Union[str, WLSError], code: Optional[int] = None):
    if isinstance(error, WLSError):
        msg = " ".join(filter(None, (error.__doc__, str(error))))
        code = WLS_ERROR_MAP.get(error.__class__)
    if not code:
        code = REQUEST_PARAM_ERROR
    if req and req.fail:
        resp = wls.generate_failure(code, req)
        return redirect(resp.redirect_url)
    else:
        return make_response(f"<p><strong>Error!</strong> {msg}</p>", 400)


@app.get("/")
def index():
    user = get_user()
    if user:
        status = f"signed in as {user}"
        action = "sign out"
        route = url_for("oidc_logout")
    else:
        status = "not signed in"
        action = "sign in"
        route = url_for("oidc_authenticate")
    return f"""
    <p>This is a ucam-wls-bridge server.</p>
    <p>You are {status} &ndash; <a href="{route}">{action} here</a>.</p>
    """


@app.get("/wls/authenticate")
def wls_authenticate():
    query = request.query_string.decode()
    try:
        req = parse_wls(query)
    except WLSFail as e:
        fail(*e.args)
    user = get_user()
    if user:
        desc = f" ({req.desc})" if req.desc else ""
        msg = f"You're authenticating to {req.url}{desc}."
        action = f"Authenticate as {user}"
    else:
        msg = "You need to sign in first."
        action = "Sign in"
    return f"""
    <p>{msg}</p>
    <form method="post">
      <input type="submit" value="{action}">
    </form>
    """


@app.post("/wls/authenticate")
def wls_authenticate_submit():
    query = request.query_string.decode()
    try:
        req = parse_wls(query)
    except WLSFail as e:
        fail(*e.args)
    user = get_user()
    if user:
        expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=6)
        principal = AuthPrincipal(user, ["pwd"], ["current"], expiry)
        wls_resp = wls.authenticate_active(req, principal, "pwd")
        return redirect(wls_resp.redirect_url)
    else:
        return oidc_authenticate(query)


@app.get("/oidc/authenticate")
def oidc_authenticate(state: Optional[str] = None):
    kwargs = {"state": state} if state else {}
    return upstream.authorize_redirect(url_for("oidc_callback", _external=True), **kwargs)


@app.get("/oidc/callback")
def oidc_callback():
    try:
        token = upstream.authorize_access_token()
    except OAuthError as e:
        return fail(None, f"{e.error}: {e.description}", AUTH_DECLINED)
    user = token["userinfo"]["preferred_username"]
    if OIDC_EMAIL_DOMAIN:
        if "@" not in user:
            return fail(None, f"Missing email domain.", AUTH_DECLINED)
        user, domain = user.split("@", 1)
        if domain != OIDC_EMAIL_DOMAIN:
            return fail(None, f"Invalid email domain {domain!r}.", AUTH_DECLINED)
    set_user(user)
    state = request.args["state"]
    try:
        AuthRequest.from_query_string(state)
    except WLSError as e:
        return redirect(url_for("index"))
    else:
        return redirect(url_for("wls_authenticate", **parse_qs(state)))


@app.get("/oidc/logout")
def oidc_logout():
    set_user(None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
