"""Unit tests for the probe client; all network operations are mocked."""

import base64
import json
import os
import re
import socket
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import agent


TOKEN = "test-server-token-that-is-at-least-24-chars"
CONFIG = agent.Config(
    worker_url="https://probe.example",
    server_id="edge_1",
    token=TOKEN,
)


class FakeResponse:
    def __init__(self, status=200, body=b""):
        self.status = status
        self._body = body

    def read(self, amount=-1):
        if amount is None or amount < 0:
            amount = len(self._body)
        value, self._body = self._body[:amount], self._body[amount:]
        return value


class FakeConnection:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.request_args = None
        self.closed = False

    def request(self, *args, **kwargs):
        self.request_args = (args, kwargs)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class FakeSocket:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.connected_to = None
        self.closed = False
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def bind(self, address):
        self.bound_to = address

    def connect(self, address):
        self.connected_to = address
        if self.connect_error:
            raise self.connect_error

    def close(self):
        self.closed = True


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class AdvancingStopEvent:
    def __init__(self, clock):
        self.clock = clock
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, seconds):
        self.clock.advance(seconds)
        return self.stopped


class ClientTests(unittest.TestCase):
    def test_public_ip_lookup_uses_ip_endpoint_and_normalizes_address(self):
        connection = FakeConnection(FakeResponse(200, b'{"ip":"2001:0db8::1"}'))
        with mock.patch.object(agent, "_connection", return_value=connection) as make_connection:
            result = agent.get_public_ip(CONFIG.worker_url, socket.AF_INET6)

        self.assertEqual(result, "2001:db8::1")
        make_connection.assert_called_once_with(CONFIG.worker_url, socket.AF_INET6, 4)
        args, kwargs = connection.request_args
        self.assertEqual(args[:2], ("GET", "/api/ip"))
        self.assertEqual(kwargs["headers"]["Connection"], "close")
        self.assertTrue(connection.closed)

    def test_public_ip_lookup_rejects_wrong_family_and_malformed_responses(self):
        wrong_family = FakeConnection(FakeResponse(200, b'{"ip":"192.0.2.7"}'))
        malformed = FakeConnection(FakeResponse(200, b"not json"))

        with mock.patch.object(agent, "_connection", side_effect=[wrong_family, malformed]):
            self.assertIsNone(agent.get_public_ip(CONFIG.worker_url, socket.AF_INET6))
            self.assertIsNone(agent.get_public_ip(CONFIG.worker_url, socket.AF_INET))

    def test_public_ip_lookup_returns_null_when_worker_has_no_address(self):
        connection = FakeConnection(FakeResponse(200, b'{"ip":null}'))
        with mock.patch.object(agent, "_connection", return_value=connection):
            self.assertIsNone(agent.get_public_ip(CONFIG.worker_url, socket.AF_INET))

    def test_connection_selects_a_socket_class_for_each_address_family(self):
        ipv4 = agent._connection(CONFIG.worker_url, socket.AF_INET, 4)
        ipv6 = agent._connection(CONFIG.worker_url, socket.AF_INET6, 4)
        dual_stack = agent._connection(CONFIG.worker_url, socket.AF_UNSPEC, 10)

        self.assertEqual(ipv4.address_family, socket.AF_INET)
        self.assertEqual(ipv6.address_family, socket.AF_INET6)
        self.assertEqual(dual_stack.address_family, socket.AF_UNSPEC)
        self.assertTrue(ipv4._context.check_hostname)
        self.assertEqual(ipv4._context.verify_mode, agent.ssl.CERT_REQUIRED)

    def test_family_connector_retries_each_resolved_address_without_real_network(self):
        first = FakeSocket(connect_error=OSError("unreachable"))
        second = FakeSocket()
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.2", 443)),
        ]

        with mock.patch.object(socket, "getaddrinfo", return_value=records) as getaddrinfo, mock.patch.object(
            socket, "socket", side_effect=[first, second]
        ):
            connected = agent._connect_for_family("probe.example", 443, 4, None, socket.AF_INET)

        self.assertIs(connected, second)
        self.assertTrue(first.closed)
        self.assertEqual(second.connected_to, ("192.0.2.2", 443))
        self.assertEqual(second.timeout, 4)
        self.assertEqual(getaddrinfo.call_args.args[2], socket.AF_INET)

    def test_family_connector_reserves_time_for_ipv4_after_a_slow_ipv6_attempt(self):
        clock = FakeClock()

        class DelayedSocket(FakeSocket):
            def connect(self, address):
                self.connected_to = address
                clock.advance(self.timeout)
                raise socket.timeout("simulated black-holed IPv6 address")

        ipv6 = DelayedSocket()
        ipv4 = FakeSocket()
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::1", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443)),
        ]

        with mock.patch.object(socket, "getaddrinfo", return_value=records) as getaddrinfo, mock.patch.object(
            socket, "socket", side_effect=[ipv6, ipv4]
        ), mock.patch.object(agent.time, "monotonic", side_effect=clock.monotonic):
            connected = agent._connect_for_family(
                "probe.example", 443, 10, None, socket.AF_UNSPEC
            )

        self.assertIs(connected, ipv4)
        self.assertEqual(ipv6.timeout, 5)
        self.assertEqual(ipv4.connected_to, ("192.0.2.1", 443))
        self.assertEqual(ipv4.timeout, 5)
        self.assertTrue(ipv6.closed)
        self.assertEqual(getaddrinfo.call_args.args[2], socket.AF_UNSPEC)

    def test_heartbeat_posts_both_addresses_with_server_bearer_token(self):
        connection = FakeConnection(FakeResponse(200, b'{"ok":true}'))
        addresses = agent.PublicAddresses("203.0.113.9", "2001:db8::9")
        with mock.patch.object(agent, "_connection", return_value=connection) as make_connection:
            result = agent.post_heartbeat(CONFIG, addresses)

        self.assertEqual(result, (True, "HTTP 200"))
        make_connection.assert_called_once_with(CONFIG.worker_url, socket.AF_UNSPEC, 10)
        args, kwargs = connection.request_args
        self.assertEqual(args[:2], ("POST", "/api/heartbeat/edge_1"))
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer " + TOKEN)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(kwargs["body"].decode("utf-8")),
            {"ipv4": "203.0.113.9", "ipv6": "2001:db8::9"},
        )
        self.assertEqual(int(kwargs["headers"]["Content-Length"]), len(kwargs["body"]))
        self.assertTrue(connection.closed)

    def test_one_shot_heartbeat_uses_fresh_nulls_when_addresses_are_unavailable(self):
        stop_event = threading.Event()
        with mock.patch.object(agent, "discover_addresses", return_value=agent.PublicAddresses()) as discover, mock.patch.object(
            agent, "post_heartbeat", return_value=(True, "HTTP 200")
        ) as post, mock.patch.object(agent, "log_result"):
            result = agent.run(CONFIG, once=True, stop_event=stop_event)

        self.assertEqual(result, 0)
        discover.assert_called_once_with(CONFIG)
        post.assert_called_once_with(CONFIG, agent.PublicAddresses(None, None))

    def test_public_addresses_refresh_every_five_minutes(self):
        clock = FakeClock()
        stop_event = AdvancingStopEvent(clock)
        posts = []

        def post(_config, _addresses):
            posts.append(clock.now)
            if len(posts) == 11:
                stop_event.stopped = True
            return True, "HTTP 200"

        with mock.patch.object(agent.time, "monotonic", side_effect=clock.monotonic), mock.patch.object(
            agent, "discover_addresses", return_value=agent.PublicAddresses("203.0.113.1", None)
        ) as discover, mock.patch.object(agent, "post_heartbeat", side_effect=post), mock.patch.object(
            agent, "log_result"
        ):
            self.assertEqual(agent.run(CONFIG, once=False, stop_event=stop_event), 0)

        self.assertEqual(posts, [float(second) for second in range(0, 330, 30)])
        self.assertEqual(discover.call_count, 2)
        self.assertEqual(agent.IP_REFRESH_SECONDS, 300)

    def test_config_rejects_non_loopback_http_origins(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as config_file:
            config_file.write(
                json.dumps(
                    {
                        "workerUrl": "http://worker.example",
                        "serverId": "edge_1",
                        "token": TOKEN,
                    }
                )
            )
            config_path = config_file.name
        try:
            with self.assertRaises(agent.ConfigError):
                agent.load_config(config_path)
        finally:
            os.unlink(config_path)

    def test_rendered_installer_unpack_stage_restores_embedded_files_once(self):
        agent_dir = Path(__file__).resolve().parent
        install_template = (agent_dir / "install.sh").read_text(encoding="utf-8")
        config_bytes = json.dumps(
            {
                "workerUrl": "https://probe.example",
                "serverId": "agent-test",
                "token": "installer-test-token-that-is-at-least-24-chars",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        expected_files = {
            "config.json": config_bytes,
            "agent.py": (agent_dir / "agent.py").read_bytes(),
            "service.template": (agent_dir / "server-probe.service").read_bytes(),
        }
        embedded = {
            "CONFIG_B64": base64.b64encode(expected_files["config.json"]).decode("ascii"),
            "AGENT_B64": base64.b64encode(expected_files["agent.py"]).decode("ascii"),
            "SERVICE_B64": base64.b64encode(expected_files["service.template"]).decode("ascii"),
        }
        markers = {
            "CONFIG_B64": "CONFIG_BASE64",
            "AGENT_B64": "AGENT_BASE64",
            "SERVICE_B64": "SERVICE_BASE64",
        }
        rendered = install_template
        for name, value in embedded.items():
            rendered = rendered.replace(
                "{}='__{}__'".format(name, markers[name]),
                "{}='{}'".format(name, value),
            )

        assignment_lines = [
            line for line in rendered.splitlines()
            if any(line.startswith(name + "=") for name in embedded)
        ]
        function_match = re.search(
            r"(?ms)^decode_embedded_files\(\) \{\n.*?^\}", rendered
        )
        self.assertEqual(len(assignment_lines), 3)
        self.assertIsNotNone(function_match)

        bash = shutil.which("bash")
        if not bash and os.name == "nt":
            candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
            if candidate.is_file():
                bash = str(candidate)
        if not bash:
            self.skipTest("Bash is required to exercise the installer unpack stage")

        harness = "\n".join(
            [
                "set -euo pipefail",
                *assignment_lines,
                function_match.group(0),
                'decode_embedded_files "$1"',
            ]
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            output_dir = work_dir / "unpacked"
            output_dir.mkdir()
            harness_path = work_dir / "unpack-test.sh"
            harness_path.write_text(harness, encoding="utf-8")
            environment = os.environ.copy()
            if os.name == "nt":
                git_bin = Path(bash).resolve().parent
                git_usr_bin = git_bin.parent / "usr" / "bin"
                environment["PATH"] = str(git_usr_bin) + os.pathsep + environment.get("PATH", "")
            result = subprocess.run(
                [bash, str(harness_path), str(output_dir)],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for filename, expected in expected_files.items():
                self.assertEqual((output_dir / filename).read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
