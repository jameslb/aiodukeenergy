import base64
import json
from datetime import datetime, timedelta, timezone

import aiohttp
import jwt
import pytest
from aioresponses import aioresponses
from cryptography.hazmat.primitives.asymmetric import rsa
from yarl import URL

from aiodukeenergy import (
    Auth0Client,
    DukeEnergyAuthError,
    DukeEnergyOAuthCallbackError,
)
from aiodukeenergy.auth0 import _AUTH0_CLIENT, MOBILE_USER_AGENT

CLIENT_ID = "PitoKqxMh8thrFF8rRlYGrAs3LbSD2dj"
CALLBACK = "https://login.duke-energy.com/ios/com.duke-energy.app/callback"
TOKEN_URL = "https://login.duke-energy.com/oauth/token"  # noqa: S105
JWKS_URL = "https://login.duke-energy.com/.well-known/jwks.json"
ISSUER = "https://login.duke-energy.com/"


def _request_headers(mocked, method: str, url: str) -> dict[str, str]:
    """Return headers captured for one mocked request."""
    return mocked.requests[(method, URL(url))][0].kwargs["headers"]


@pytest.fixture
def signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    return private_key, {"keys": [jwk]}


def make_id_token(private_key, expected_nonce: str, **overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "auth0|user",
        "internal_identifier": "DUKE_USER",
        "email": "user@example.com",
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "nonce": expected_nonce,
        **overrides,
    }
    return jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-key"}
    )


def callback(transaction, *, code="authorization-code", state=None) -> str:
    return f"{CALLBACK}?code={code}&state={state or transaction.state}"


@pytest.mark.asyncio
async def test_successful_manual_callback(signing_material):
    private_key, jwks = signing_material
    async with aiohttp.ClientSession() as session:
        client = Auth0Client(session)
        transaction = client.create_authorization_transaction()
        token = {
            "access_token": "access",
            "refresh_token": "refresh",
            "id_token": make_id_token(private_key, transaction.nonce),
            "token_type": "Bearer",
            "expires_in": 86400,
        }
        with aioresponses() as mocked:
            mocked.post(TOKEN_URL, payload=token)
            mocked.get(JWKS_URL, payload=jwks)
            result = await client.complete_authorization(
                transaction, callback(transaction)
            )
            assert _request_headers(mocked, "POST", TOKEN_URL)["User-Agent"] == (
                MOBILE_USER_AGENT
            )
            assert _request_headers(mocked, "GET", JWKS_URL)["User-Agent"] == (
                MOBILE_USER_AGENT
            )

    assert result.token == token
    assert result.id_token_claims["internal_identifier"] == "DUKE_USER"
    assert transaction.redirect_uri == CALLBACK


@pytest.mark.parametrize(
    "url",
    [
        "http://login.duke-energy.com/ios/com.duke-energy.app/callback?code=x&state=s",
        "https://evil.example/ios/com.duke-energy.app/callback?code=x&state=s",
        "https://login.duke-energy.com/wrong?code=x&state=s",
        "https://user@login.duke-energy.com/ios/com.duke-energy.app/callback?code=x&state=s",
    ],
)
def test_wrong_callback_origin_or_path(url):
    with pytest.raises(DukeEnergyAuthError, match="Invalid Duke Energy callback"):
        Auth0Client.validate_callback_url(url, "s")


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("state=s", "exactly one code"),
        ("code=&state=s", "exactly one code"),
        ("code=a&code=b&state=s", "exactly one code"),
        ("code=a", "exactly one state"),
        ("code=a&state=", "exactly one state"),
        ("code=a&state=s&state=t", "exactly one state"),
    ],
)
def test_missing_or_duplicate_callback_values(query, message):
    with pytest.raises(DukeEnergyAuthError, match=message):
        Auth0Client.validate_callback_url(f"{CALLBACK}?{query}", "s")


def test_state_mismatch():
    with pytest.raises(DukeEnergyAuthError, match="state mismatch"):
        Auth0Client.validate_callback_url(f"{CALLBACK}?code=a&state=wrong", "s")


def test_oauth_error_callback():
    with pytest.raises(DukeEnergyOAuthCallbackError) as raised:
        Auth0Client.validate_callback_url(
            f"{CALLBACK}?error=access_denied&error_description=Login+cancelled&state=s",
            "s",
        )
    assert raised.value.error == "access_denied"
    assert raised.value.description == "Login cancelled"


@pytest.mark.asyncio
async def test_failed_code_exchange():
    async with aiohttp.ClientSession() as session:
        client = Auth0Client(session)
        transaction = client.create_authorization_transaction()
        with aioresponses() as mocked:
            mocked.post(TOKEN_URL, status=400, body="invalid grant")
            with pytest.raises(DukeEnergyAuthError, match="Token exchange failed"):
                await client.complete_authorization(transaction, callback(transaction))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_overrides", "expected"),
    [
        ({"nonce": "wrong"}, "nonce mismatch"),
        ({"iss": "https://wrong.example/"}, "validation failed"),
        ({"aud": "wrong-client"}, "validation failed"),
        (
            {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
            "validation failed",
        ),
    ],
)
async def test_invalid_id_token_claims(signing_material, claim_overrides, expected):
    private_key, jwks = signing_material
    async with aiohttp.ClientSession() as session:
        client = Auth0Client(session)
        transaction = client.create_authorization_transaction()
        id_token = make_id_token(private_key, transaction.nonce, **claim_overrides)
        with aioresponses() as mocked:
            mocked.get(JWKS_URL, payload=jwks)
            with pytest.raises(DukeEnergyAuthError, match=expected):
                await client.validate_id_token(id_token, transaction.nonce)


@pytest.mark.asyncio
async def test_invalid_id_token_signature(signing_material):
    _, jwks = signing_material
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    async with aiohttp.ClientSession() as session:
        client = Auth0Client(session)
        token = make_id_token(other_key, "nonce")
        with aioresponses() as mocked:
            mocked.get(JWKS_URL, payload=jwks)
            with pytest.raises(DukeEnergyAuthError, match="validation failed"):
                await client.validate_id_token(token, "nonce")


@pytest.mark.asyncio
async def test_refresh_token_after_manual_setup():
    async with aiohttp.ClientSession() as session:
        client = Auth0Client(session)
        refreshed = {
            "access_token": "new-access",
            "id_token": "new-id-token",
            "expires_in": 86400,
        }
        with aioresponses() as mocked:
            mocked.post(TOKEN_URL, payload=refreshed)
            assert await client.refresh_token("refresh") == refreshed
            assert _request_headers(mocked, "POST", TOKEN_URL)["User-Agent"] == (
                MOBILE_USER_AGENT
            )


def test_mobile_client_metadata_matches_current_duke_app():
    """Auth0 telemetry identifies the current supported mobile client."""
    metadata = json.loads(base64.b64decode(_AUTH0_CLIENT))
    assert metadata["env"]["iOS"] == "27.0"
    assert metadata["version"] == "2.19.0"
