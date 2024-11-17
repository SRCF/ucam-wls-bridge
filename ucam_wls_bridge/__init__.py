from datetime import datetime, timedelta, timezone
from functools import reduce
from importlib import import_module
import os
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from urllib.parse import parse_qs, urlsplit

from flask import Flask, redirect, render_template, request, session, url_for

from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import FlaskOAuth2App, OAuth

from ucam_wls import AuthPrincipal, AuthRequest, load_private_key, LoginService
from ucam_wls.errors import NoMutualAuthType, ProtocolVersionUnsupported, WLSError
from ucam_wls.status import AUTH_DECLINED, NO_MUTUAL_AUTH_TYPES, REQUEST_PARAM_ERROR, UNSUPPORTED_PROTO_VER, USER_CANCEL


User = Tuple[str, List[str]]  # username, ptags
Handler = Callable[[Dict[str, Any]], User]

_SESSION_KEY = "uwb_auth"
SESSION_USERNAME_KEY = f"{_SESSION_KEY}_username"
SESSION_PTAGS_KEY = f"{_SESSION_KEY}_ptags"

WLS_ERROR_MAP: Dict[Type[WLSError], int] = {
    NoMutualAuthType: NO_MUTUAL_AUTH_TYPES,
    ProtocolVersionUnsupported: UNSUPPORTED_PROTO_VER,
}


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

handler: Optional[Handler] = None


class WLSFail(Exception):
    pass


def get_user() -> Union[User, Tuple[None, None]]:
    try:
        return (session[SESSION_USERNAME_KEY], session[SESSION_PTAGS_KEY])
    except KeyError:
        return (None, None)

def set_user(username: str, ptags: List[str]):
    session[SESSION_USERNAME_KEY] = username
    session[SESSION_PTAGS_KEY] = ptags

def clear_user():
    session.pop(SESSION_USERNAME_KEY, None)
    session.pop(SESSION_PTAGS_KEY, None)


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
    else:
        msg = error
    if not code:
        code = REQUEST_PARAM_ERROR
    if not req or req.fail:
        return render_template("error.j2", msg=msg, code=code)
    else:
        resp = wls.generate_failure(code, req)
        return redirect(resp.redirect_url)


@app.get("/")
def index():
    username, ptags = get_user()
    return render_template("index.j2", username=username, ptags=ptags)


@app.get("/wls/authenticate")
def wls_authenticate():
    query = request.query_string.decode()
    try:
        req = parse_wls(query)
    except WLSFail as e:
        return fail(*e.args)
    username, ptags = get_user()
    domain = urlsplit(req.url).netloc
    return render_template(
        "authenticate.j2",
        username=username,
        ptags=ptags,
        domain=domain,
        url=req.url,
        desc=req.desc,
    )


@app.post("/wls/authenticate")
def wls_authenticate_submit():
    query = request.query_string.decode()
    try:
        req = parse_wls(query)
    except WLSFail as e:
        return fail(*e.args)
    action = request.form.get("action")
    if action == "cancel":
        return fail(req, "User declined authentication.", USER_CANCEL)
    username, ptags = get_user()
    if username:
        expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=6)
        principal = AuthPrincipal(username, ["pwd"], ptags, expiry)
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
    ptags: List[str]
    if handler:
        try:
            username, ptags = handler(token["userinfo"])
        except LookupError as e:
            msg = e.args[0] if e.args else "Declined by service configuration."
            return fail(None, msg, AUTH_DECLINED)
    else:
        username = token["userinfo"]["preferred_username"]
        ptags = []
    set_user(username, ptags)
    state = request.args["state"]
    try:
        AuthRequest.from_query_string(state)
    except WLSError as e:
        return redirect(url_for("index"))
    else:
        return redirect(url_for("wls_authenticate", **parse_qs(state)))


@app.get("/oidc/logout")
def oidc_logout():
    clear_user()
    return redirect(url_for("index"))


if os.environ.get("UWB_OIDC_HANDLER"):
    _handler_module, _handler_attribute = os.environ["UWB_OIDC_HANDLER"].split(":")
    handler = reduce(getattr, _handler_attribute.split("."), import_module(_handler_module))


if __name__ == "__main__":
    app.run()
