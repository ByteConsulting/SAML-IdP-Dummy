import base64
from datetime import datetime, timedelta, timezone
import os
import urllib.parse
import uuid
import zlib
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from lxml import etree
from signxml import XMLSigner

app = FastAPI(title="DMU SAML IdP")

IDP_ENTITY_ID = "https://auth.my-gamez.com/saml/metadata"
TENANT_ID = "eeacdbf6-7e71-4be4-92be-e4ab1ae783b8"
DEFAULT_USER = "gast@my-gamez.com"
AVD_TARGET_URL = f"https://client.wvd.microsoft.com/arm/webclient/index.html?tenant={TENANT_ID}"


def get_keys() -> tuple[bytes, bytes]:
    env_key = os.getenv("SAML_PRIVATE_KEY")
    env_cert = os.getenv("SAML_PUBLIC_CERT")

    if env_key and env_cert:
        return env_key.encode("utf-8"), env_cert.encode("utf-8")

    with open("idp_private.key", "rb") as f:
        key_data = f.read()
    with open("idp_public.cer", "rb") as f:
        cert_data = f.read()
    return key_data, cert_data


def extract_request_id(saml_request_b64: str) -> str:
    if not saml_request_b64:
        return ""
    try:
        raw = base64.b64decode(urllib.parse.unquote(saml_request_b64))
        try:
            decompressed = zlib.decompress(raw, -15)
        except Exception:
            decompressed = raw
        root = etree.fromstring(decompressed)
        return root.get("ID", "")
    except Exception:
        return ""


@app.api_route(
    "/saml/login", methods=["GET", "POST"], response_class=HTMLResponse
)
async def login_page(request: Request):
    saml_request = ""
    relay_state = ""

    if request.method == "POST":
        form_data = await request.form()
        saml_request = str(form_data.get("SAMLRequest", ""))
        relay_state = str(form_data.get("RelayState", ""))
    else:
        saml_request = request.query_params.get("SAMLRequest", "")
        relay_state = request.query_params.get("RelayState", "")

    # FALL 1: Benutzer ruft die Seite direkt im Browser auf (kein SAML-Request vorhanden)
    # Zeige die saubere DMU-ID Maske. Der Klick startet den Handshake mit Tenant- & User-Hints.
    if not saml_request:
        bootstrap_target = (
            f"{AVD_TARGET_URL}"
            f"&login_hint={urllib.parse.quote(DEFAULT_USER)}"
            f"&domain_hint=my-gamez.com"
        )
        return f"""
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DMU Workspace Access</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #f8fafc; }}
                .card {{ background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 380px; border: 1px solid #334155; }}
                h2 {{ margin-top: 0; font-size: 1.5rem; text-align: center; margin-bottom: 1.5rem; }}
                .badge {{ display: inline-block; background: #0284c7; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; vertical-align: middle; }}
                .form-group {{ margin-bottom: 1.2rem; }}
                label {{ display: block; margin-bottom: .4rem; font-size: 0.85rem; color: #94a3b8; }}
                input {{ width: 100%; padding: .65rem; background: #0f172a; border: 1px solid #475569; border-radius: 6px; box-sizing: border-box; color: #f8fafc; font-size: 0.95rem; }}
                a.btn {{ display: block; text-align: center; box-sizing: border-box; width: 100%; padding: .75rem; background: #2563eb; color: white; border-radius: 6px; font-weight: 600; text-decoration: none; font-size: 1rem; margin-top: 1rem; }}
                a.btn:hover {{ background: #1d4ed8; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>DMU-ID <span class="badge">SAML IdP</span></h2>
                <div class="form-group">
                    <label>E-Mail-Adresse</label>
                    <input type="email" value="{DEFAULT_USER}" readonly />
                </div>
                <div class="form-group">
                    <label>Passwort</label>
                    <input type="password" value="••••••••••••" readonly />
                </div>
                <div class="form-group">
                    <label>2. Faktor (FIDO2 / TOTP)</label>
                    <input type="text" value="654321 (Gültig)" readonly />
                </div>
                <a href="{bootstrap_target}" class="btn">Workspace starten</a>
            </div>
        </body>
        </html>
        """

    # FALL 2: Microsoft hat den Benutzer via SAMLRequest zurückgeschickt
    # Automatischer Submit in Sekundenbruchteilen ohne erneuten Klick
    return f"""
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DMU Workspace Access</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #f8fafc; }}
            .card {{ background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 380px; border: 1px solid #334155; text-align: center; }}
            .spinner {{ border: 3px solid #334155; border-top: 3px solid #38bdf8; border-radius: 50%; width: 36px; height: 36px; animation: spin 1s linear infinite; margin: 1.5rem auto 0; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
        <script>
            window.addEventListener('DOMContentLoaded', () => {{
                document.getElementById('samlForm').submit();
            }});
        </script>
    </head>
    <body>
        <div class="card">
            <h2>DMU Workspace</h2>
            <p style="color: #94a3b8; font-size: 0.9rem;">Sitzung wird autorisiert...</p>
            <div class="spinner"></div>
            <form id="samlForm" method="post" action="/saml/auth" style="display: none;">
                <input type="hidden" name="RelayState" value="{relay_state}" />
                <input type="hidden" name="SAMLRequest" value="{saml_request}" />
                <input type="email" name="username" value="{DEFAULT_USER}" />
                <input type="password" name="password" value="DummyPass123!" />
                <input type="text" name="mfa_token" value="654321" />
            </form>
        </div>
    </body>
    </html>
    """


@app.post("/saml/auth", response_class=HTMLResponse)
async def authenticate(
    username: str = Form(...),
    password: str = Form(...),
    mfa_token: str = Form(...),
    RelayState: str = Form(""),
    SAMLRequest: str = Form(""),
):
    key_pem, cert_pem = get_keys()

    final_relay_state = RelayState if RelayState else AVD_TARGET_URL

    in_response_to = extract_request_id(SAMLRequest)
    in_resp_attr = f'InResponseTo="{in_response_to}"' if in_response_to else ""

    now = datetime.now(timezone.utc)
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    response_id = f"_{uuid.uuid4()}"
    assertion_id = f"_{uuid.uuid4()}"

    recipient_acs = "https://login.microsoftonline.com/login.srf"

    saml_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{recipient_acs}"
                {in_resp_attr}>
        <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{username}</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{recipient_acs}" {in_resp_attr}/>
                </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
                <saml:AudienceRestriction>
                    <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="{issue_instant}">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
            <saml:AttributeStatement>
                <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
                    <saml:AttributeValue>{username}</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
                    <saml:AttributeValue>{username.split('@')[0]}</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences">
                    <saml:AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
    </samlp:Response>"""

    root = etree.fromstring(saml_xml.encode("utf-8"))
    assertion = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")

    signer = XMLSigner(
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    )
    signed_assertion = signer.sign(assertion, key=key_pem, cert=cert_pem)

    sig_elem = signed_assertion.find(
        "{http://www.w3.org/2000/09/xmldsig#}Signature"
    )
    if sig_elem is not None:
        signed_assertion.remove(sig_elem)
        signed_assertion.insert(1, sig_elem)

    root.remove(assertion)
    root.append(signed_assertion)

    signed_xml_bytes = etree.tostring(root, xml_declaration=False)
    saml_response_b64 = base64.b64encode(signed_xml_bytes).decode("utf-8")

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Verbinde mit AVD...</title>
        <script>
            window.onload = function() {{
                document.forms[0].submit();
            }};
        </script>
    </head>
    <body style="background: #0f172a; color: #f8fafc; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
        <p>Authentifizierung verifiziert. Weiterleitung zu Azure Virtual Desktop...</p>
        <form method="post" action="{recipient_acs}">
            <input type="hidden" name="SAMLResponse" value="{saml_response_b64}" />
            <input type="hidden" name="RelayState" value="{final_relay_state}" />
            <noscript><button type="submit">Weiter</button></noscript>
        </form>
    </body>
    </html>
    """