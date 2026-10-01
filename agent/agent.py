#!/usr/bin/env python3
"""Report periodic heartbeats and the public addresses seen by the worker."""

import argparse
import http.client
import ipaddress
import json
import re
import signal
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


SERVER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{24,256}$")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_CONFIG_PATH = "/etc/server-probe.json"
IP_REQUEST_TIMEOUT_SECONDS = 4
IP_REFRESH_SECONDS = 300
MAX_IP_RESPONSE_BYTES = 1024
MIN_CONNECT_ATTEMPT_SECONDS = 0.25


@dataclass(frozen=True)
class Config:
    worker_url: str
    server_id: str
    token: str
    interval_seconds: int = 30
    request_timeout_seconds: int = 10


@dataclass(frozen=True)
class PublicAddresses:
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None


class ConfigError(ValueError):
    pass


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError("{} must be a positive integer".format(field))
    return value


def _validate_worker_url(value: Any) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ConfigError("workerUrl must be a URL")
    if "?" in value or "#" in value:
        raise ConfigError("workerUrl must not contain a query or fragment")

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port also validates malformed and out-of-range ports.
        parsed.port
    except ValueError:
        raise ConfigError("workerUrl is not a valid URL")

    if parsed.scheme not in ("https", "http") or not hostname:
        raise ConfigError("workerUrl must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("workerUrl must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ConfigError("workerUrl must be an origin without a path, query, or fragment")
    if parsed.scheme == "http" and hostname.lower() not in LOOPBACK_HOSTS:
        raise ConfigError("workerUrl must use HTTPS except on localhost")

    # Keep the configured origin exactly, after rejecting URL components that
    # could change where the bearer-authenticated request is sent.
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def load_config(config_path: str) -> Config:
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            raw = json.load(config_file)
    except OSError:
        raise ConfigError("cannot read config file")
    except json.JSONDecodeError:
        raise ConfigError("config file is not valid JSON")

    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")

    worker_url = _validate_worker_url(raw.get("workerUrl"))
    server_id = raw.get("serverId")
    if not isinstance(server_id, str) or not SERVER_ID_PATTERN.fullmatch(server_id):
        raise ConfigError("serverId must contain 1 to 64 letters, digits, underscores, or hyphens")

    token = raw.get("token")
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        raise ConfigError("token must be 24 to 256 URL-safe characters")

    interval = _positive_int(raw.get("intervalSeconds", 30), "intervalSeconds")
    timeout = _positive_int(raw.get("requestTimeoutSeconds", 10), "requestTimeoutSeconds")
    if timeout > 120:
        raise ConfigError("requestTimeoutSeconds must be at most 120")

    return Config(worker_url, server_id, token, interval, timeout)


def _connect_for_family(host: str, port: int, timeout: float, source_address: Any, family: int) -> socket.socket:
    """Connect only to addresses in one family, trying each DNS result in turn."""
    deadline = time.monotonic() + timeout
    candidates = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    last_error = None
    for index, (address_family, socktype, protocol, _canonical_name, sockaddr) in enumerate(candidates):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise last_error or socket.timeout("connection timed out")
        candidates_left = len(candidates) - index
        attempt_timeout = min(
            remaining,
            max(MIN_CONNECT_ATTEMPT_SECONDS, remaining / candidates_left),
        )
        sock = socket.socket(address_family, socktype, protocol)
        try:
            sock.settimeout(attempt_timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as error:
            last_error = error
            sock.close()

    if last_error is not None:
        raise last_error
    raise OSError("no address available for requested IP family")


class _FamilyHTTPConnection(http.client.HTTPConnection):
    """An HTTP connection whose DNS lookup is constrained to one IP family."""

    address_family = socket.AF_UNSPEC

    def connect(self) -> None:
        self.sock = _connect_for_family(
            self.host, self.port, self.timeout, self.source_address, self.address_family
        )
        if self._tunnel_host:
            self._tunnel()


class _FamilyHTTPConnection4(_FamilyHTTPConnection):
    address_family = socket.AF_INET


class _FamilyHTTPConnection6(_FamilyHTTPConnection):
    address_family = socket.AF_INET6


class _FamilyHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection with family-pinned DNS and default TLS verification."""

    address_family = socket.AF_UNSPEC

    def connect(self) -> None:
        raw_socket = _connect_for_family(
            self.host, self.port, self.timeout, self.source_address, self.address_family
        )
        try:
            if self._tunnel_host:
                self.sock = raw_socket
                self._tunnel()
                raw_socket = self.sock
            context = self._context or ssl.create_default_context()
            self.sock = context.wrap_socket(
                raw_socket, server_hostname=self._tunnel_host or self.host
            )
        except Exception:
            raw_socket.close()
            raise


class _FamilyHTTPSConnection4(_FamilyHTTPSConnection):
    address_family = socket.AF_INET


class _FamilyHTTPSConnection6(_FamilyHTTPSConnection):
    address_family = socket.AF_INET6


def _connection(worker_url: str, family: int, timeout: float) -> http.client.HTTPConnection:
    parsed = urlsplit(worker_url)
    port = parsed.port
    if parsed.scheme == "https":
        connection_class = {
            socket.AF_INET: _FamilyHTTPSConnection4,
            socket.AF_INET6: _FamilyHTTPSConnection6,
        }.get(family, _FamilyHTTPSConnection)
        return connection_class(parsed.hostname, port=port, timeout=timeout)
    connection_class = {
        socket.AF_INET: _FamilyHTTPConnection4,
        socket.AF_INET6: _FamilyHTTPConnection6,
    }.get(family, _FamilyHTTPConnection)
    return connection_class(parsed.hostname, port=port, timeout=timeout)


def get_public_ip(worker_url: str, family: int, timeout: float = IP_REQUEST_TIMEOUT_SECONDS) -> Optional[str]:
    """Ask the worker for the source IP of a request forced through one family."""
    connection = _connection(worker_url, family, timeout)
    try:
        connection.request("GET", "/api/ip", headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            response.read(MAX_IP_RESPONSE_BYTES)
            return None
        body = response.read(MAX_IP_RESPONSE_BYTES)
        if response.read(1):
            return None
        decoded = json.loads(body.decode("utf-8"))
        raw_ip = decoded.get("ip") if isinstance(decoded, dict) else None
        if raw_ip is None:
            return None
        if not isinstance(raw_ip, str):
            return None
        address = ipaddress.ip_address(raw_ip)
        expected_version = 4 if family == socket.AF_INET else 6
        if address.version != expected_version:
            return None
        return str(address)
    except (OSError, http.client.HTTPException, UnicodeError, ValueError, ssl.SSLError):
        # DNS, TLS, network, or malformed API responses are reported as absent.
        return None
    finally:
        connection.close()


def discover_addresses(config: Config) -> PublicAddresses:
    """Refresh each family independently so one unavailable route stays null."""
    return PublicAddresses(
        ipv4=get_public_ip(config.worker_url, socket.AF_INET),
        ipv6=get_public_ip(config.worker_url, socket.AF_INET6),
    )


def post_heartbeat(config: Config, addresses: PublicAddresses) -> Tuple[bool, str]:
    payload = json.dumps(
        {"ipv4": addresses.ipv4, "ipv6": addresses.ipv6}, separators=(",", ":")
    ).encode("utf-8")
    endpoint = "/api/heartbeat/{}".format(config.server_id)
    connection = _connection(config.worker_url, socket.AF_UNSPEC, config.request_timeout_seconds)
    try:
        connection.request(
            "POST",
            endpoint,
            body=payload,
            headers={
                "Authorization": "Bearer " + config.token,
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        response.read(MAX_IP_RESPONSE_BYTES)
        if 200 <= response.status < 300:
            return True, "HTTP {}".format(response.status)
        return False, "HTTP {}".format(response.status)
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return False, "network error"
    finally:
        connection.close()


def log_result(server_id: str, ok: bool, detail: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    outcome = "heartbeat accepted" if ok else "heartbeat failed ({})".format(detail)
    print("{} server_id={} {}".format(timestamp, server_id, outcome), flush=True)


def run(config: Config, once: bool, stop_event: threading.Event) -> int:
    next_attempt = time.monotonic()
    next_ip_refresh = 0.0
    addresses = PublicAddresses()
    while not stop_event.is_set():
        delay = next_attempt - time.monotonic()
        if delay > 0 and stop_event.wait(delay):
            break

        now = time.monotonic()
        if now >= next_ip_refresh:
            addresses = discover_addresses(config)
            next_ip_refresh = time.monotonic() + IP_REFRESH_SECONDS
            if stop_event.is_set():
                break

        ok, detail = post_heartbeat(config, addresses)
        log_result(config.server_id, ok, detail)
        if once:
            return 0 if ok else 1

        next_attempt += config.interval_seconds
        now = time.monotonic()
        while next_attempt <= now:
            next_attempt += config.interval_seconds

    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Send heartbeats to a Cloudflare Workers probe service")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="JSON config file (default: {})".format(DEFAULT_CONFIG_PATH),
    )
    parser.add_argument("--once", action="store_true", help="send one heartbeat and exit")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as error:
        print("configuration error: {}".format(error), file=sys.stderr)
        return 2

    stop_event = threading.Event()

    def request_stop(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    return run(config, args.once, stop_event)


if __name__ == "__main__":
    sys.exit(main())
