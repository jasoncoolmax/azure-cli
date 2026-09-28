# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import json
import os
import socket
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


if __name__ == "__main__":
    unittest.main()
