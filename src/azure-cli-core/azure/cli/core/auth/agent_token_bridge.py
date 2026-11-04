# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
import os
import re
import socket
import stat
import struct
import sys
import time
from urllib.parse import urlsplit

from knack.util import CLIError


_MAXIMUM_MESSAGE_LENGTH = 64 * 1024
_DEFAULT_REDIRECT_URI = "msauth.com.msauth.unsignedapp://auth"
_ENABLE_ENVIRONMENT_VARIABLE = "AZURE_CLI_AGENT_TOKEN_BRIDGE"
_STANDALONE_PROTOCOL = "standalone-v1"
_MAXIMUM_STANDALONE_MESSAGE_LENGTH = 1024 * 1024
_active_standalone_credential = None


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
        self._protocol = os.environ.get("AGENT_TOKEN_BRIDGE_PROTOCOL", "native-json-v1")
        self._access_key_file = os.environ.get("AGENT_TOKEN_BRIDGE_ACCESS_KEY_FILE")
        self._runtime_connection = None
        self._runtime_handles = set()
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

        if self._protocol == _STANDALONE_PROTOCOL:
            return self._request_standalone_token(
                scopes,
                claims_challenge,
                extra_query_parameters,
                interactive,
            )
        if self._protocol != "native-json-v1":
            raise CLIError("Unsupported AgentTokenBridge protocol.")

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

    def _request_standalone_token(
            self, scopes, claims_challenge, extra_query_parameters, interactive):
        global _active_standalone_credential
        self._connect_standalone()
        destination_host = _destination_host(scopes)
        fields = [
            ("op", "acquire"),
            ("authority", self._authority),
            ("client_id", self._client_id),
            ("destination_host", destination_host),
            ("destination_port", "443"),
            ("lifetime_seconds", "3600"),
            ("interactive", "true" if interactive else "false"),
            (
                "parameters",
                json.dumps(
                    {
                        "redirectUri": self._redirect_uri,
                        "extraQueryParameters": extra_query_parameters,
                    },
                    separators=(",", ":"),
                ),
            ),
        ]
        fields.extend(("scope", scope) for scope in scopes)
        if self._account_identifier:
            fields.append(("account_identifier", self._account_identifier))
        if claims_challenge:
            fields.append(("claims_challenge", claims_challenge))

        _send_standalone_message(self._runtime_connection, fields)
        response = _receive_standalone_message(self._runtime_connection)
        if _field(response, "status") != "ok":
            from azure.cli.core.azclierror import AuthenticationError
            raise AuthenticationError("The standalone AgentTokenBridge token request failed.")

        placeholder = _field(response, "placeholder")
        handle = _field(response, "handle")
        expires_at = _parse_expiration(_field(response, "expires_at"))
        account_identifier = _field(response, "account_identifier")
        if (
            not re.fullmatch(r"ATB_[a-f0-9]{64}", placeholder)
            or not handle
            or not account_identifier
        ):
            raise CLIError("The standalone AgentTokenBridge returned an invalid response.")

        self._runtime_handles.add(handle)
        self._account_identifier = account_identifier
        _active_standalone_credential = self
        return {
            "access_token": placeholder,
            "token_type": "Bearer",
            "expires_in": int(expires_at - time.time()),
            "expires_at": expires_at,
            "account_identifier": account_identifier,
        }

    def _connect_standalone(self):
        if self._runtime_connection is not None:
            return
        if not self._access_key_file:
            raise CLIError(
                "AGENT_TOKEN_BRIDGE_ACCESS_KEY_FILE is required for standalone-v1.")
        _validate_socket(self._socket_path)
        access_key = _read_private_value(self._access_key_file)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(600)
        try:
            connection.connect(self._socket_path)
            _send_standalone_message(
                connection,
                [("op", "hello"), ("key", access_key)],
            )
            response = _receive_standalone_message(connection)
            if _field(response, "status") != "ok":
                raise CLIError("Standalone AgentTokenBridge authentication failed.")
            _configure_standalone_proxy(
                _field(response, "proxy_url"),
                _field(response, "ca_file"),
            )
            self._runtime_connection = connection
        except Exception:
            connection.close()
            raise


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


def _read_private_value(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, encoding="utf-8") as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise CLIError(
                    "AgentTokenBridge access key must be private and owned by this user.")
            value = source.read(4097)
    except OSError as ex:
        raise CLIError("Unable to read AgentTokenBridge access key.") from ex
    if not value or len(value) > 4096:
        raise CLIError("AgentTokenBridge access key is invalid.")
    return value.strip()


def _destination_host(scopes):
    hosts = set()
    for scope in scopes:
        parsed = urlsplit(scope)
        if parsed.scheme != "https" or not parsed.hostname:
            raise CLIError("Standalone AgentTokenBridge requires HTTPS resource scopes.")
        host = parsed.hostname.lower()
        if host == "management.core.windows.net":
            host = "management.azure.com"
        hosts.add(host)
    if len(hosts) != 1:
        raise CLIError(
            "Standalone AgentTokenBridge requires scopes for one destination host.")
    return hosts.pop()


def _configure_standalone_proxy(proxy_url, ca_file):
    parsed = urlsplit(proxy_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise CLIError("Standalone AgentTokenBridge returned an invalid proxy URL.")
    try:
        metadata = os.lstat(ca_file)
    except OSError as ex:
        raise CLIError("Standalone AgentTokenBridge CA file is unavailable.") from ex
    if (
        not os.path.isabs(ca_file)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
    ):
        raise CLIError("Standalone AgentTokenBridge returned an unsafe CA file.")

    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["https_proxy"] = proxy_url
    os.environ["REQUESTS_CA_BUNDLE"] = ca_file
    os.environ["CURL_CA_BUNDLE"] = ca_file
    os.environ["SSL_CERT_FILE"] = ca_file
    os.environ["NO_PROXY"] = ""
    os.environ["no_proxy"] = ""


def _send_standalone_message(connection, fields):
    payload = bytearray(struct.pack("!H", len(fields)))
    for key, value in fields:
        key_bytes = key.encode("utf-8")
        value_bytes = value.encode("utf-8")
        if not key_bytes or len(key_bytes) > 65535:
            raise CLIError("Invalid standalone AgentTokenBridge field.")
        payload.extend(struct.pack("!H", len(key_bytes)))
        payload.extend(key_bytes)
        payload.extend(struct.pack("!I", len(value_bytes)))
        payload.extend(value_bytes)
    if not payload or len(payload) > _MAXIMUM_STANDALONE_MESSAGE_LENGTH:
        raise CLIError("Standalone AgentTokenBridge request is too large.")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _receive_exact(connection, length):
    value = bytearray()
    while len(value) < length:
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise CLIError("Standalone AgentTokenBridge closed the connection.")
        value.extend(chunk)
    return bytes(value)


def _receive_standalone_message(connection):
    length = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if not 0 < length <= _MAXIMUM_STANDALONE_MESSAGE_LENGTH:
        raise CLIError("Standalone AgentTokenBridge response length is invalid.")
    payload = memoryview(_receive_exact(connection, length))
    offset = 0

    def consume(format_string):
        nonlocal offset
        size = struct.calcsize(format_string)
        if offset + size > len(payload):
            raise CLIError("Standalone AgentTokenBridge response is malformed.")
        value = struct.unpack_from(format_string, payload, offset)[0]
        offset += size
        return value

    fields = []
    field_count = consume("!H")
    if field_count > 256:
        raise CLIError("Standalone AgentTokenBridge returned too many fields.")
    for _ in range(field_count):
        key_length = consume("!H")
        if offset + key_length > len(payload):
            raise CLIError("Standalone AgentTokenBridge response is malformed.")
        key = bytes(payload[offset:offset + key_length]).decode("utf-8")
        offset += key_length
        value_length = consume("!I")
        if offset + value_length > len(payload):
            raise CLIError("Standalone AgentTokenBridge response is malformed.")
        value = bytes(payload[offset:offset + value_length]).decode("utf-8")
        offset += value_length
        fields.append((key, value))
    if offset != len(payload):
        raise CLIError("Standalone AgentTokenBridge response has trailing data.")
    return fields


def _field(fields, name):
    for key, value in fields:
        if key == name:
            return value
    raise CLIError("Standalone AgentTokenBridge response is missing a field.")


def _parse_expiration(value):
    try:
        expires_at = float(value)
    except ValueError as ex:
        raise CLIError(
            "Standalone AgentTokenBridge returned an invalid expiration.") from ex
    if expires_at <= time.time():
        raise CLIError("Standalone AgentTokenBridge returned an expired credential.")
    return expires_at


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
