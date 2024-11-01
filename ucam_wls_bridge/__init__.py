from datetime import datetime, timedelta, timezone
import os
from typing import Dict, Optional, Tuple, Type, Union
from urllib.parse import urlsplit

from flask import Flask, make_response, redirect, request, url_for

from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import FlaskOAuth2App, OAuth

from ucam_wls import AuthPrincipal, AuthRequest, load_private_key, LoginService
from ucam_wls.errors import InvalidAuthRequest, NoMutualAuthType, ProtocolVersionUnsupported, WLSError
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


def fail(error: Union[Tuple[str, int], WLSError], req: Optional[AuthRequest] = None):
    if isinstance(error, WLSError):
        msg = " ".join(filter(None, (error.__doc__, str(error))))
        code = WLS_ERROR_MAP.get(error.__class__, REQUEST_PARAM_ERROR)
    else:
        msg, code = error
    if req and req.fail:
        resp = wls.generate_failure(code, req)
        return redirect(resp.redirect_url)
    else:
        return make_response(f"<strong>Error!</strong> {msg}", 400)


@app.get("/wls/authenticate")
def wls_authenticate():
    query = request.query_string.decode()
    try:
        wls_req = AuthRequest.from_query_string(query)
    except (InvalidAuthRequest, ProtocolVersionUnsupported) as e:
        return fail(e)
    if not wls.have_mutual_auth_type(wls_req):
        return fail(NoMutualAuthType(), wls_req)
    parts = urlsplit(wls_req.url)
    if not parts.netloc:
        return fail(("No return domain specified.", REQUEST_PARAM_ERROR), wls_req)
    if parts.scheme != "https" and parts.netloc != "localhost":
        return fail(("Insecure web application.", REQUEST_PARAM_ERROR), wls_req)
    return upstream.authorize_redirect(url_for("oidc_callback", _external=True), state=query)


@app.get("/oidc/callback")
def oidc_callback():
    try:
        query = request.args["state"]
    except KeyError:
        return fail(("OAuth2 state missing.", REQUEST_PARAM_ERROR))
    try:
        wls_req = AuthRequest.from_query_string(query)
    except (InvalidAuthRequest, ProtocolVersionUnsupported) as e:
        return fail(e)
    try:
        token = upstream.authorize_access_token()
    except OAuthError as e:
        return fail((f"{e.error}: {e.description}", AUTH_DECLINED), wls_req)
    user = token["userinfo"]["preferred_username"]
    if OIDC_EMAIL_DOMAIN and "@" in user:
        user, domain = user.split("@", 1)
        if domain != OIDC_EMAIL_DOMAIN:
            return fail((f"Invalid email domain {domain!r}.", AUTH_DECLINED), wls_req)
    expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=6)
    principal = AuthPrincipal(user, ["pwd"], ["current"], expiry)
    wls_resp = wls.authenticate_active(wls_req, principal, "pwd")
    return redirect(wls_resp.redirect_url)


if __name__ == "__main__":
    app.run()
