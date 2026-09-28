# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
import os
import socket
import stat
import sys
import time

from knack.util import CLIError


_MAXIMUM_MESSAGE_LENGTH = 64 * 1024
_DEFAULT_REDIRECT_URI = "msauth.com.msauth.unsignedapp://auth"
_ENABLE_ENVIRONMENT_VARIABLE = "AZURE_CLI_AGENT_TOKEN_BRIDGE"


def is_agent_token_bridge_enabled():
    value = os.environ.get(_ENABLE_ENVIRONMENT_VARIABLE, "")
    return value.lower() in ("1", "true", "yes")


class AgentTokenBridgeCredential:
    """User credential that delegates token acquisition to AgentTokenBridge."""

    def __init__(self, client_id, authority, account_identifier=None):
        if sys.platform != "darwin":
            raise CLIError("AgentTokenBridge is only supported on macOS.")

        self._client_id = client_id
        self._authority = authority
        self._account_identifier = account_identifier
        self._socket_path = os.environ.get(
            "AGENT_TOKEN_BRIDGE_SOCKET_PATH",
            os.path.expanduser("~/.agent-token-bridge/agent-token-bridge.sock"))
        self._redirect_uri = os.environ.get(
            "AGENT_TOKEN_BRIDGE_REDIRECT_URI",
            _DEFAULT_REDIRECT_URI)
        self._cache = {}

    def acquire_token_interactive(self, scopes, claims_challenge=None):
        result = self._request_token(
            scopes,
            claims_challenge=claims_challenge,
            interactive=True)
        account_identifier = result.get("account_identifier")
        if not account_identifier:
            raise CLIError("AgentTokenBridge did not return an account identifier.")
        self._account_identifier = account_identifier
        return result

    def acquire_token(self, scopes, claims_challenge=None, **kwargs):
        if kwargs.get("data"):
            raise CLIError("AgentTokenBridge does not support data-bound token requests.")
        if not self._account_identifier:
            raise CLIError("No AgentTokenBridge account is available. Run `az login`.")

        agentic_session = os.environ.get("COPILOT_AGENT_SESSION_ID")
        use_cache = not claims_challenge and not agentic_session
        cache_key = (tuple(sorted(scopes)), claims_challenge)
        cached_result = self._cache.get(cache_key)
        if use_cache and cached_result and cached_result["expires_at"] - time.time() > 300:
            return {
                "access_token": cached_result["access_token"],
                "token_type": "Bearer",
                "expires_in": int(cached_result["expires_at"] - time.time()),
            }

        result = self._request_token(
            scopes,
            claims_challenge=claims_challenge,
            interactive=False)
        if use_cache:
            self._cache[cache_key] = {
                "access_token": result["access_token"],
                "expires_at": result["expires_at"],
            }
        return result

    def _request_token(self, scopes, claims_challenge, interactive):
        if not scopes or not all(isinstance(scope, str) and scope for scope in scopes):
            raise CLIError("Azure CLI requested invalid token scopes.")

        extra_query_parameters = {}
        from .agentic_session import build_agentic_session_params, merge_access_token_claims
        agentic_session_id, agentic_claims = build_agentic_session_params()
        if agentic_session_id:
            extra_query_parameters["client_session"] = agentic_session_id
            claims_challenge = merge_access_token_claims(claims_challenge, agentic_claims)

            from azure.cli.core.telemetry import set_agentic_session
            set_agentic_session(True)

        slice_name = os.environ.get("AGENT_TOKEN_BRIDGE_SLICE")
        if slice_name:
            extra_query_parameters["slice"] = slice_name
        data_center = os.environ.get("AGENT_TOKEN_BRIDGE_DC")
        if data_center:
            extra_query_parameters["dc"] = data_center

        request = {
            "operation": "acquireToken",
            "clientId": self._client_id,
            "authority": self._authority,
            "redirectUri": self._redirect_uri,
            "scopes": list(scopes),
            "interactive": interactive,
            "validateAuthority": True,
        }
        if self._account_identifier:
            request["accountIdentifier"] = self._account_identifier
        if claims_challenge:
            request["claims"] = claims_challenge
        if extra_query_parameters:
            request["extraQueryParameters"] = extra_query_parameters
        if interactive:
            request["promptType"] = 1

        response = _send_request(request, self._socket_path)
        if response.get("success") is not True:
            from azure.cli.core.azclierror import AuthenticationError
            domain = response.get("errorDomain", "AgentTokenBridge")
            code = response.get("errorCode", 0)
            description = response.get("errorDescription", "Token acquisition failed.")
            raise AuthenticationError("{}: {} ({}).".format(description, domain, code))

        access_token = response.get("accessToken")
        expires_on = response.get("expiresOn")
        if not isinstance(access_token, str) or not access_token:
            raise CLIError("AgentTokenBridge returned an invalid access token.")
        if not isinstance(expires_on, (int, float)) or expires_on <= time.time():
            raise CLIError("AgentTokenBridge returned an invalid token expiration.")

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": int(expires_on - time.time()),
            "expires_at": float(expires_on),
            "account_identifier": response.get("accountIdentifier"),
        }


def _validate_socket(socket_path):
    try:
        socket_status = os.lstat(socket_path)
    except OSError as ex:
        raise CLIError("Unable to inspect AgentTokenBridge socket: {}.".format(ex.strerror)) from ex

    if not stat.S_ISSOCK(socket_status.st_mode):
        raise CLIError("AgentTokenBridge path is not a Unix-domain socket.")
    if socket_status.st_uid != os.getuid():
        raise CLIError("AgentTokenBridge socket is not owned by the current user.")
    if stat.S_IMODE(socket_status.st_mode) != 0o600:
        raise CLIError("AgentTokenBridge socket must have mode 0600.")


def _send_request(request, socket_path):
    _validate_socket(socket_path)
    message = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(message) > _MAXIMUM_MESSAGE_LENGTH:
        raise CLIError("AgentTokenBridge request exceeds 64 KiB.")

    response_bytes = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(600)
            connection.connect(socket_path)
            connection.sendall(message)
            while b"\n" not in response_bytes:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response_bytes.extend(chunk)
                if len(response_bytes) > _MAXIMUM_MESSAGE_LENGTH:
                    raise CLIError("AgentTokenBridge response exceeds 64 KiB.")
    except OSError as ex:
        raise CLIError("Unable to communicate with AgentTokenBridge: {}.".format(ex)) from ex

    response_line = bytes(response_bytes).split(b"\n", 1)[0]
    if not response_line:
        raise CLIError("AgentTokenBridge returned an empty response.")
    try:
        response = json.loads(response_line)
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        raise CLIError("AgentTokenBridge returned invalid JSON.") from ex
    if not isinstance(response, dict):
        raise CLIError("AgentTokenBridge response must be a JSON object.")
    return response
