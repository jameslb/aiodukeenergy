"""
Auth0 authentication client for Duke Energy.

This module handles OAuth2/OIDC authentication with Duke Energy's Auth0 tenant
using the mobile app flow. Authentication requires a browser-based login flow
since automated login is blocked by CAPTCHA.

Flow:
1. Call get_authorization_url() to get a URL for the user to open in a browser
2. User logs in via browser and gets redirected to
   https://login.duke-energy.com/ios/ URL with code
3. Copy the complete callback URL from the browser address bar
4. Validate the callback and exchange its code for tokens
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import aiohttp
import jwt
import yarl

from .exceptions import DukeEnergyAuthError, DukeEnergyOAuthCallbackError

_LOGGER = logging.getLogger(__name__)

# Auth0 configuration for Duke Energy
_AUTH0_DOMAIN = "login.duke-energy.com"
_AUTH0_BASE_URL = yarl.URL(f"https://{_AUTH0_DOMAIN}")
_AUTHORIZE_URL = _AUTH0_BASE_URL / "authorize"
_TOKEN_URL = _AUTH0_BASE_URL / "oauth" / "token"
_USERINFO_URL = _AUTH0_BASE_URL / "userinfo"
_JWKS_URL = _AUTH0_BASE_URL / ".well-known" / "jwks.json"
_ISSUER = f"https://{_AUTH0_DOMAIN}/"
MOBILE_USER_AGENT = "Duke%20Energy/1374 CFNetwork/3896.100.1.2.1 Darwin/27.0.0"

# Mobile app client configuration (required for Duke Energy API token exchange)
_CLIENT_ID = "PitoKqxMh8thrFF8rRlYGrAs3LbSD2dj"
# _REDIRECT_URI = "cma-prod://login.duke-energy.com/ios/com.dukeenergy.customerapp.release/callback"
_REDIRECT_URI = "https://login.duke-energy.com/ios/com.duke-energy.app/callback"
_AUTH0_CLIENT = base64.b64encode(
    json.dumps(
        {
            "env": {"iOS": "27.0", "swift": "6.x"},
            "version": "2.19.0",
            "name": "Auth0.swift",
        }
    ).encode()
).decode()


@dataclass(frozen=True, slots=True)
class AuthorizationTransaction:
    """Transient data for one Duke Energy authorization attempt."""

    authorize_url: str
    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str = _REDIRECT_URI


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    """Validated tokens and identity claims from an authorization attempt."""

    token: dict[str, Any]
    id_token_claims: dict[str, Any]


def _generate_pkce_pair() -> tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge (S256).

    Returns a tuple of (code_verifier, code_challenge).
    """
    # Generate code_verifier (43-128 chars, URL-safe)
    code_verifier = secrets.token_urlsafe(32)

    # Generate code_challenge = BASE64URL(SHA256(code_verifier))
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return code_verifier, code_challenge


def _generate_state() -> str:
    """Generate a random URL-safe state value."""
    return secrets.token_urlsafe(32)


def _generate_nonce() -> str:
    """Generate a random URL-safe nonce value."""
    return secrets.token_urlsafe(32)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode a JWT token without verification.

    :param token: The JWT token to decode.
    :returns: The decoded token payload.
    """
    return jwt.decode(token, options={"verify_signature": False})


def is_token_expired(token: str) -> bool:
    """
    Check if a JWT token is expired.

    :param token: The JWT token to check.
    :returns: True if the token is expired, False otherwise.
    """
    try:
        payload = decode_token(token)
        exp = payload.get("exp")
        if exp is None:
            return True
        return datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc)
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return True


def extract_code_from_url(url: str) -> str | None:
    """
    Extract authorization code from redirect URL.

    :param url: The redirect URL containing the code parameter.
    :returns: The authorization code, or None if not found.
    """
    try:
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return None
    codes = query.get("code", [])
    return codes[0] if len(codes) == 1 and codes[0] else None


class Auth0Client:
    """
    Auth0 authentication client for Duke Energy.

    This client handles the OAuth2/OIDC flow with Duke Energy's Auth0 tenant.
    It uses the mobile app configuration which is required to get an id_token
    that can be exchanged for a Duke Energy API access token.

    Example usage:
        client = Auth0Client(session)

        # Generate authorization URL for browser login
        auth_url, state, code_verifier = client.get_authorization_url()

        # User opens auth_url in browser, logs in, gets redirected to https://login.duke-energy.com/ios/
        # Copy the complete callback URL from the browser address bar

        # Exchange code for tokens
        tokens = await client.exchange_code(code, code_verifier)
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> None:
        """
        Initialize the Auth0 client.

        :param session: The aiohttp session to use for requests.
        :param timeout: Request timeout in seconds.
        """
        self.session = session
        self.timeout = timeout
        self._code_verifier: str | None = None

    def get_authorization_url(self) -> tuple[str, str, str]:
        """
        Generate the authorization URL for browser-based OAuth flow.

        This method generates PKCE credentials and builds an authorization URL
        that can be opened in a browser. After the user logs in, they will be
        redirected to a https://login.duke-energy.com/ios/
        URL containing an authorization code.

        Use the Chrome extension from ./chrome-extension/ to capture
        the authorization code from the redirect.

        :returns: Tuple of (authorize_url, state, code_verifier).
                  Save the code_verifier - it's needed for token exchange.
        """
        self._code_verifier, code_challenge = _generate_pkce_pair()
        state = _generate_state()
        nonce = _generate_nonce()

        params = {
            "client_id": _CLIENT_ID,
            "scope": "openid profile email offline_access",
            "redirect_uri": _REDIRECT_URI,
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": _AUTH0_CLIENT,
        }

        query = "&".join(f"{k}={v}" for k, v in params.items())
        authorize_url = f"{_AUTHORIZE_URL}?{query}"

        return authorize_url, state, self._code_verifier

    def create_authorization_transaction(self) -> AuthorizationTransaction:
        """Create a complete, transient PKCE authorization transaction."""
        code_verifier, code_challenge = _generate_pkce_pair()
        state = _generate_state()
        nonce = _generate_nonce()
        params = {
            "client_id": _CLIENT_ID,
            "scope": "openid profile email offline_access",
            "redirect_uri": _REDIRECT_URI,
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": _AUTH0_CLIENT,
        }
        return AuthorizationTransaction(
            authorize_url=str(_AUTHORIZE_URL.with_query(params)),
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
        )

    @staticmethod
    def validate_callback_url(callback_url: str, expected_state: str) -> str:
        """Validate a pasted Duke callback URL and return its authorization code."""
        try:
            parsed = urlsplit(callback_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
        except ValueError as err:
            raise DukeEnergyAuthError("Invalid callback URL") from err

        try:
            valid_origin = (
                parsed.scheme == "https"
                and parsed.hostname == _AUTH0_DOMAIN
                and parsed.port in (None, 443)
                and parsed.path == "/ios/com.duke-energy.app/callback"
                and parsed.username is None
                and parsed.password is None
            )
        except ValueError as err:
            raise DukeEnergyAuthError("Invalid Duke Energy callback URL") from err
        if not valid_origin:
            raise DukeEnergyAuthError("Invalid Duke Energy callback URL")

        states = query.get("state", [])
        if len(states) != 1 or not states[0]:
            raise DukeEnergyAuthError("Callback must contain exactly one state")
        if not secrets.compare_digest(states[0], expected_state):
            raise DukeEnergyAuthError("OAuth state mismatch")

        errors = query.get("error", [])
        if errors:
            if len(errors) != 1 or not errors[0]:
                raise DukeEnergyAuthError("Invalid OAuth error callback")
            descriptions = query.get("error_description", [])
            description = descriptions[0] if len(descriptions) == 1 else None
            raise DukeEnergyOAuthCallbackError(errors[0], description)

        codes = query.get("code", [])
        if len(codes) != 1 or not codes[0]:
            raise DukeEnergyAuthError("Callback must contain exactly one code")
        return codes[0]

    async def complete_authorization(
        self,
        transaction: AuthorizationTransaction,
        callback_url: str,
    ) -> AuthorizationResult:
        """Validate a callback, exchange its code, and verify the ID token."""
        code = self.validate_callback_url(callback_url, transaction.state)
        token = await self.exchange_code(code, transaction.code_verifier)
        claims = await self.validate_id_token(token.get("id_token"), transaction.nonce)
        return AuthorizationResult(token=token, id_token_claims=claims)

    async def validate_id_token(
        self, id_token: str | None, expected_nonce: str
    ) -> dict[str, Any]:
        """Cryptographically validate an Auth0 ID token and its nonce."""
        if not id_token:
            raise DukeEnergyAuthError("Token response did not include an ID token")
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise DukeEnergyAuthError("ID token has an invalid signing header")
            response = await self.session.get(
                _JWKS_URL,
                headers={
                    "Accept": "application/json",
                    "auth0-client": _AUTH0_CLIENT,
                    "User-Agent": MOBILE_USER_AGENT,
                },
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
            if response.status != 200:
                raise DukeEnergyAuthError(
                    f"Unable to retrieve ID token signing keys: {response.status}"
                )
            jwks = await response.json()
            matching_keys = [
                key for key in jwks.get("keys", []) if key.get("kid") == header["kid"]
            ]
            if len(matching_keys) != 1:
                raise DukeEnergyAuthError("ID token signing key was not found")
            signing_key = jwt.PyJWK.from_dict(matching_keys[0]).key
            claims: dict[str, Any] = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=_CLIENT_ID,
                issuer=_ISSUER,
                options={"require": ["exp", "iss", "aud", "nonce"]},
            )
            nonce = claims.get("nonce")
            if not isinstance(nonce, str) or not secrets.compare_digest(
                nonce, expected_nonce
            ):
                raise DukeEnergyAuthError("ID token nonce mismatch")
        except DukeEnergyAuthError:
            raise
        except (aiohttp.ClientError, ValueError, jwt.PyJWTError) as err:
            raise DukeEnergyAuthError("ID token validation failed") from err
        return claims

    async def exchange_code(
        self, code: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        """
        Exchange an authorization code for tokens.

        Use this after browser-based login to exchange the code from the
        redirect URL for access and refresh tokens.

        :param code: The authorization code from the redirect URL.
        :param code_verifier: The PKCE code_verifier from get_authorization_url().
                              If not provided, uses the internally stored verifier.
        :returns: Token response containing access_token, refresh_token, id_token, etc.
        :raises DukeEnergyAuthError: If the exchange fails.
        """
        if code_verifier:
            self._code_verifier = code_verifier

        if not self._code_verifier:
            raise DukeEnergyAuthError(
                "Code verifier not set. Call get_authorization_url() first "
                "or provide code_verifier parameter."
            )

        _LOGGER.debug("Exchanging authorization code for tokens")

        headers = {
            "accept-language": "en_US",
            "auth0-client": _AUTH0_CLIENT,
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": MOBILE_USER_AGENT,
        }

        response = await self.session.post(
            _TOKEN_URL,
            headers=headers,
            json={
                "grant_type": "authorization_code",
                "client_id": _CLIENT_ID,
                "code_verifier": self._code_verifier,
                "code": code,
                "redirect_uri": _REDIRECT_URI,
            },
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )

        if response.status != 200:
            text = await response.text()
            _LOGGER.error("Token exchange failed: %s", text)
            raise DukeEnergyAuthError(
                f"Token exchange failed: {response.status} - {text}"
            )

        result = await response.json()
        _LOGGER.debug("Token exchange successful")
        return result

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh the access token using a refresh token.

        :param refresh_token: The refresh token.
        :returns: Token response containing new access_token, refresh_token, etc.
        :raises DukeEnergyAuthError: If refresh fails.
        """
        _LOGGER.debug("Refreshing access token")

        headers = {
            "accept-language": "en_US",
            "auth0-client": _AUTH0_CLIENT,
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": MOBILE_USER_AGENT,
        }

        response = await self.session.post(
            _TOKEN_URL,
            headers=headers,
            json={
                "grant_type": "refresh_token",
                "client_id": _CLIENT_ID,
                "refresh_token": refresh_token,
            },
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )

        if response.status != 200:
            text = await response.text()
            if response.status == 429 or response.status >= 500:
                response.raise_for_status()
            _LOGGER.error("Token refresh failed: %s", text)
            raise DukeEnergyAuthError(
                f"Token refresh failed: {response.status} - {text}"
            )

        result = await response.json()
        _LOGGER.debug("Token refresh successful")
        return result

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Auth0.

        :param access_token: The access token.
        :returns: User info containing email, sub, etc.
        """
        response = await self.session.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        response.raise_for_status()
        return await response.json()
