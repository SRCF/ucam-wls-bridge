# ucam-wls-bridge

This is a Web Login Service (WLS) for the Ucam-WebAuth aka. WAA2WLS protocol, which defers to an OpenID Connect (OIDC) server for the underlying authentication.

## Key generation

Generate an RSA private key using OpenSSL:

```
openssl genrsa -out private.pem 4096
```

Extract the corresponding public key in `RSA PUBLIC KEY` format:

```
ssh-keygen -f private.pem -e -m pem >public.pub
```

## WLS configuration

Environment variables:

- `UWB_SECRET_KEY`: randomly-generated string used to secure session cookies
- `UWB_OIDC_URL`: URL to the upstream OIDC server's discovery document e.g. `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`
- `UWB_OIDC_CLIENT_ID`: client identifier for an app registration on the OIDC server
- `UWB_OIDC_CLIENT_SECRET`: corresponding client secret for that app registration
- `UWB_OIDC_EMAIL_DOMAIN`: (optional) if the preferred username returned by the OIDC server is an email address, require it to be on this domain and return just the local part
- `UWB_KEY_FILE`: path to an RSA private key used to sign WLS responses
- `UWB_KEY_ID`: integer key ID used to identify the above key

## Running the service

Using Flask's development server:

```
flask --app ucam_wls_bridge run
```

Using gunicorn:

```
gunicorn --access-logfile - --error-logfile - --capture-output --bind unix:web.sock ucam_wls_bridge:app
```

## WAA (client) configuration

Most Ucam-WebAuth clients are configured with Raven's keys out of the box.  You'll need to add the RSA public key that corresponds to your server's private key, along with setting the service authenticate and logout URLs.

Using [python-ucam-webauth](https://github.com/danielrichman/python-ucam-webauth):

```python
import ucam_webauth

class WLSRequest(ucam_webauth.Request):
    def __str__(self):
        query_string = super().__str__(self)
        return "https://{service-host}/wls/authenticate?" + query_string

class WLSResponse(ucam_webauth.Response):
    keys = {}
    with open("{public-key-path}", "rb") as f:
        keys["{key-id}"] = ucam_webauth.rsa.load_key(f.read())

class WLSAuthDecorator(ucam_webauth.flask_glue.AuthDecorator):
    request_class = WLSRequest
    response_class = WLSResponse
    logout_url = "https://{service-host}/oidc/logout"
```

Using [mod_ucam_webauth](https://github.com/cambridgeuniversity/mod_ucam_webauth) on Apache:

```
AAAuthService https://{service-host}/wls/authenticate
AALogoutService https://{service-host}/oidc/logout
AAKeyDir {public-key-dir}
```
