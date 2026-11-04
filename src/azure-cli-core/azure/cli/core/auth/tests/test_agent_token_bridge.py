# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from azure.cli.core.azclierror import AuthenticationError
from azure.cli.core.auth.agent_token_bridge import AgentTokenBridgeCredential
from knack.util import CLIError


class _MockBridge:

    def __init__(self, socket_path, responses):
        self.socket_path = socket_path
        self.responses = list(responses)
        self.requests = []
        self.error = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("Mock bridge did not start.")

    def join(self):
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("Mock bridge did not finish.")
        if self.error:
            raise self.error

    def _serve(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.socket_path))
                os.chmod(self.socket_path, 0o600)
                server.listen(len(self.responses))
                self._ready.set()
                for response in self.responses:
                    connection, _ = server.accept()
                    with connection:
                        request_bytes = bytearray()
                        while b"\n" not in request_bytes:
                            chunk = connection.recv(4096)
                            if not chunk:
                                raise RuntimeError("Client closed before sending a request.")
                            request_bytes.extend(chunk)
                        request_line = bytes(request_bytes).split(b"\n", 1)[0]
                        self.requests.append(json.loads(request_line))
                        connection.sendall(json.dumps(response).encode("utf-8") + b"\n")
        except Exception as ex:  # pylint: disable=broad-except
            self.error = ex
            self._ready.set()


def _read_exact(connection, length):
    value = bytearray()
    while len(value) < length:
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise RuntimeError("Client closed before sending a complete message.")
        value.extend(chunk)
    return bytes(value)


def _read_binary_message(connection):
    length = struct.unpack("!I", _read_exact(connection, 4))[0]
    payload = memoryview(_read_exact(connection, length))
    offset = 0

    def consume(format_string):
        nonlocal offset
        size = struct.calcsize(format_string)
        value = struct.unpack_from(format_string, payload, offset)[0]
        offset += size
        return value

    fields = []
    for _ in range(consume("!H")):
        key_length = consume("!H")
        key = bytes(payload[offset:offset + key_length]).decode("utf-8")
        offset += key_length
        value_length = consume("!I")
        value = bytes(payload[offset:offset + value_length]).decode("utf-8")
        offset += value_length
        fields.append((key, value))
    return fields


def _write_binary_message(connection, fields):
    payload = bytearray(struct.pack("!H", len(fields)))
    for key, value in fields:
        key = key.encode("utf-8")
        value = value.encode("utf-8")
        payload.extend(struct.pack("!H", len(key)))
        payload.extend(key)
        payload.extend(struct.pack("!I", len(value)))
        payload.extend(value)
    connection.sendall(struct.pack("!I", len(payload)) + payload)


class _MockStandaloneBridge:

    def __init__(self, socket_path, ca_file, access_key):
        self.socket_path = socket_path
        self.ca_file = ca_file
        self.access_key = access_key
        self.requests = []
        self.error = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("Mock standalone bridge did not start.")

    def join(self):
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("Mock standalone bridge did not finish.")
        if self.error:
            raise self.error

    def _serve(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.socket_path))
                os.chmod(self.socket_path, 0o600)
                server.listen(1)
                self._ready.set()
                connection, _ = server.accept()
                with connection:
                    hello = _read_binary_message(connection)
                    self.requests.append(hello)
                    self.assert_field(hello, "key", self.access_key)
                    _write_binary_message(connection, [
                        ("status", "ok"),
                        ("proxy_url", "http://127.0.0.1:18080"),
                        ("ca_file", str(self.ca_file)),
                    ])
                    acquire = _read_binary_message(connection)
                    self.requests.append(acquire)
                    _write_binary_message(connection, [
                        ("status", "ok"),
                        ("handle", "cred-test"),
                        ("placeholder", "ATB_" + "a" * 64),
                        ("expires_at", str(int(time.time()) + 3600)),
                        ("account_identifier", "opaque-account-id"),
                    ])
        except Exception as ex:  # pylint: disable=broad-except
            self.error = ex
            self._ready.set()

    @staticmethod
    def assert_field(fields, name, expected):
        value = next((value for key, value in fields if key == name), None)
        if value != expected:
            raise AssertionError("{} did not match.".format(name))


@unittest.skipUnless(sys.platform == "darwin", "AgentTokenBridge is macOS-only")
class TestAgentTokenBridgeCredential(unittest.TestCase):

    def test_interactive_and_silent_requests_preserve_client_id(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            socket_path = Path(temp_directory) / "bridge.sock"
            bridge = _MockBridge(
                socket_path,
                [
                    {
                        "success": True,
                        "accessToken": "interactive-token",
                        "expiresOn": time.time() + 3600,
                        "accountIdentifier": "account-id",
                    },
                    {
                        "success": True,
                        "accessToken": "silent-token",
                        "expiresOn": time.time() + 3600,
                        "accountIdentifier": "account-id",
                    },
                    {
                        "success": True,
                        "accessToken": "fresh-agent-session-token",
                        "expiresOn": time.time() + 3600,
                        "accountIdentifier": "account-id",
                    },
                ])
            bridge.start()

            with patch.dict(
                    os.environ,
                    {
                        "AGENT_TOKEN_BRIDGE_SOCKET_PATH": str(socket_path),
                        "COPILOT_AGENT_SESSION_ID": "agent-session-id",
                    },
                    clear=False):
                credential = AgentTokenBridgeCredential(
                    "caller-selected-client-id",
                    "https://login.microsoftonline.com/tenant")
                interactive_result = credential.acquire_token_interactive(["scope/.default"])
                silent_result = credential.acquire_token(["scope/.default"])
                fresh_result = credential.acquire_token(["scope/.default"])

            bridge.join()

            self.assertEqual(interactive_result["account_identifier"], "account-id")
            self.assertEqual(silent_result["access_token"], "silent-token")
            self.assertEqual(fresh_result["access_token"], "fresh-agent-session-token")
            self.assertEqual(bridge.requests[0]["clientId"], "caller-selected-client-id")
            self.assertTrue(bridge.requests[0]["interactive"])
            self.assertEqual(
                bridge.requests[0]["extraQueryParameters"]["client_session"],
                "agent-session-id")
            self.assertIn("xms_cli_sid", bridge.requests[0]["claims"])
            self.assertEqual(bridge.requests[1]["clientId"], "caller-selected-client-id")
            self.assertFalse(bridge.requests[1]["interactive"])
            self.assertEqual(bridge.requests[1]["accountIdentifier"], "account-id")
            self.assertEqual(len(bridge.requests), 3)

    def test_bridge_error_is_reported_as_authentication_error(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            socket_path = Path(temp_directory) / "bridge.sock"
            bridge = _MockBridge(
                socket_path,
                [{
                    "success": False,
                    "errorDomain": "MSALErrorDomain",
                    "errorCode": -50000,
                    "errorDescription": "Interaction is required.",
                }])
            bridge.start()

            with patch.dict(
                    os.environ,
                    {"AGENT_TOKEN_BRIDGE_SOCKET_PATH": str(socket_path)},
                    clear=False):
                credential = AgentTokenBridgeCredential(
                    "client-id",
                    "https://login.microsoftonline.com/tenant")
                with self.assertRaisesRegex(AuthenticationError, "Interaction is required"):
                    credential.acquire_token_interactive(["scope/.default"])

            bridge.join()

    def test_socket_with_group_access_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            socket_path = Path(temp_directory) / "bridge.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(socket_path))
                os.chmod(socket_path, 0o660)

                with patch.dict(
                        os.environ,
                        {"AGENT_TOKEN_BRIDGE_SOCKET_PATH": str(socket_path)},
                        clear=False):
                    credential = AgentTokenBridgeCredential(
                        "client-id",
                        "https://login.microsoftonline.com/tenant")
                    with self.assertRaisesRegex(CLIError, "mode 0600"):
                        credential.acquire_token_interactive(["scope/.default"])

    def test_standalone_bridge_returns_only_placeholder_and_configures_proxy(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            directory = Path(temp_directory)
            socket_path = directory / "bridge.sock"
            access_key_file = directory / "bridge.key"
            access_key_file.write_text("test-access-key", encoding="utf-8")
            os.chmod(access_key_file, 0o600)
            ca_file = directory / "ca.pem"
            ca_file.write_text("test-ca", encoding="utf-8")
            bridge = _MockStandaloneBridge(socket_path, ca_file, "test-access-key")
            bridge.start()

            environment = {
                "AGENT_TOKEN_BRIDGE_SOCKET_PATH": str(socket_path),
                "AGENT_TOKEN_BRIDGE_PROTOCOL": "standalone-v1",
                "AGENT_TOKEN_BRIDGE_ACCESS_KEY_FILE": str(access_key_file),
                "COPILOT_AGENT_SESSION_ID": "",
            }
            with patch.dict(os.environ, environment, clear=False):
                credential = AgentTokenBridgeCredential(
                    "caller-selected-client-id",
                    "https://login.microsoftonline.com/organizations")
                result = credential.acquire_token_interactive(
                    ["https://management.core.windows.net//.default"])
                self.assertEqual(result["access_token"], "ATB_" + "a" * 64)
                self.assertEqual(result["account_identifier"], "opaque-account-id")
                self.assertEqual(
                    os.environ["HTTPS_PROXY"],
                    "http://127.0.0.1:18080")
                self.assertEqual(os.environ["REQUESTS_CA_BUNDLE"], str(ca_file))

            bridge.join()
            acquire = bridge.requests[1]
            _MockStandaloneBridge.assert_field(
                acquire, "destination_host", "management.azure.com")
            _MockStandaloneBridge.assert_field(
                acquire, "client_id", "caller-selected-client-id")
            _MockStandaloneBridge.assert_field(acquire, "interactive", "true")
            self.assertNotIn(
                "access_token",
                {name for name, _ in acquire})


if __name__ == "__main__":
    unittest.main()
