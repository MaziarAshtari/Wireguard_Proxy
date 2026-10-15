"""Minimal authenticated SOCKS5/HTTP clients with remote DNS and request deadlines."""

from __future__ import annotations

import base64
import http.client
import io
import ipaddress
import json
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .core import AppError, credentials

TEST_URL = "http://cp.cloudflare.com/generate_204"
COUNTRY_URL = "https://ipinfo.io/json"


@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)


class RequestError(Exception):
    """A proxy request failed; never contains supplied credentials."""


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Request deadline exceeded.")
    return remaining


def _recv(sock: socket.socket, count: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < count:
        sock.settimeout(_remaining(deadline))
        block = sock.recv(count - len(data))
        if not block:
            raise RequestError("Proxy closed the connection.")
        data.extend(block)
    return bytes(data)


def _send(sock: socket.socket, data: bytes, deadline: float) -> None:
    sock.settimeout(_remaining(deadline))
    sock.sendall(data)


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock, self.deadline = sock, deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self.sock.settimeout(_remaining(self.deadline))
        return self.sock.recv_into(buffer)


class _ResponseSocket:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock, self.deadline = sock, deadline

    def makefile(self, *args, **kwargs):
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline))


def _socks_connect(sock: socket.socket, proxy: Proxy, host: str, port: int, deadline: float) -> None:
    _send(sock, b"\x05\x01\x02", deadline)
    if _recv(sock, 2, deadline) != b"\x05\x02":
        raise RequestError("SOCKS5 username/password authentication is required.")
    username, password = proxy.username.encode(), proxy.password.encode()
    _send(sock, b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password, deadline)
    if _recv(sock, 2, deadline) != b"\x01\x00":
        raise RequestError("SOCKS5 authentication failed.")
    try:
        address = b"\x01" + ipaddress.IPv4Address(host).packed
    except ipaddress.AddressValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise RequestError("Destination hostname is too long.")
        address = b"\x03" + bytes([len(encoded)]) + encoded
    _send(sock, b"\x05\x01\x00" + address + struct.pack("!H", port), deadline)
    version, reply, reserved, address_type = _recv(sock, 4, deadline)
    if version != 5 or reply != 0 or reserved != 0:
        raise RequestError("SOCKS5 connection failed.")
    sizes = {1: 4, 4: 16}
    size = _recv(sock, 1, deadline)[0] if address_type == 3 else sizes.get(address_type)
    if size is None:
        raise RequestError("Invalid SOCKS5 response.")
    _recv(sock, size + 2, deadline)


def _connect_http(sock: socket.socket, authority: str, auth: str, deadline: float) -> None:
    _send(sock, (f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                 f"Proxy-Authorization: Basic {auth}\r\n\r\n").encode("ascii"), deadline)
    # Read exactly the CONNECT headers; do not buffer any subsequent TLS bytes.
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= 16384:
            raise RequestError("HTTP CONNECT headers are too large.")
        header.extend(_recv(sock, 1, deadline))
    first = header.split(b"\r\n", 1)[0].split()
    if len(first) < 2 or first[1] != b"200":
        raise RequestError("HTTP CONNECT failed.")


def request(proxy: Proxy, protocol: str, url: str, timeout: float,
            max_body: int = 65536) -> tuple[int, bytes, float]:
    """Return HTTP status, bounded body, and latency in ms; never follow redirects."""
    started = time.monotonic()
    deadline = started + timeout
    sock = None
    try:
        credentials(proxy.username, proxy.password)
        target = urlsplit(url)
        if target.scheme not in ("http", "https") or not target.hostname or target.username:
            raise RequestError("An HTTP or HTTPS URL without credentials is required.")
        host = target.hostname.encode("idna").decode("ascii")
        if ":" in host or any(c in url for c in "\r\n"):
            raise RequestError("Only IPv4 destinations and hostnames are supported.")
        port = target.port or (443 if target.scheme == "https" else 80)
        authority = f"{host}:{port}"
        # Proxy hosts are numeric IPv4, so getaddrinfo cannot stall on DNS here.
        proxy_host = str(ipaddress.IPv4Address(proxy.host))
        sock = socket.create_connection((proxy_host, proxy.port), _remaining(deadline))
        auth = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode("ascii")
        if protocol == "socks5":
            _socks_connect(sock, proxy, host, port, deadline)
        elif protocol == "http":
            if target.scheme == "https":
                _connect_http(sock, authority, auth, deadline)
        else:
            raise RequestError("Unsupported proxy protocol.")
        if target.scheme == "https":
            sock.settimeout(_remaining(deadline))
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        destination = f"http://{authority}{path}" if protocol == "http" and target.scheme == "http" else path
        headers = (f"GET {destination} HTTP/1.1\r\nHost: {authority}\r\n"
                   "User-Agent: wgproxy/1\r\nConnection: close\r\n")
        if protocol == "http" and target.scheme == "http":
            headers += f"Proxy-Authorization: Basic {auth}\r\n"
        _send(sock, (headers + "\r\n").encode("ascii"), deadline)
        with http.client.HTTPResponse(_ResponseSocket(sock, deadline)) as response:
            response.begin()
            body = response.read(max_body + 1)
            if len(body) > max_body:
                raise RequestError("Response body is too large.")
            _remaining(deadline)
            return response.status, body, (time.monotonic() - started) * 1000
    except (OSError, ValueError, UnicodeError, http.client.HTTPException, AppError):
        raise RequestError("Proxy request failed or timed out.") from None
    finally:
        if sock is not None:
            sock.close()


def exit_country(proxy: Proxy, timeout: float) -> str:
    try:
        status, body, _ = request(proxy, "socks5", COUNTRY_URL, timeout)
        country = json.loads(body).get("country", "") if status == 200 else ""
        if isinstance(country, str) and len(country) == 2 and country.isascii() and country.isalpha():
            return country.upper()
    except (RequestError, ValueError, AttributeError, UnicodeError):
        pass
    return "UNKNOWN"


def public_ipv4(timeout: float) -> str:
    # Use a literal IPv4 bootstrap address and validated HTTPS, ignoring proxy env vars.
    for url in ("https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"):
        connection = http.client.HTTPSConnection(urlsplit(url).hostname, timeout=timeout)
        try:
            connection.request("GET", "/cdn-cgi/trace", headers={"User-Agent": "wgproxy/1"})
            response = connection.getresponse()
            body = response.read(4097)
            if response.status == 200 and len(body) <= 4096:
                for line in body.decode("ascii").splitlines():
                    if line.startswith("ip="):
                        address = ipaddress.IPv4Address(line[3:])
                        if address.is_global:
                            return str(address)
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            pass
        finally:
            connection.close()
    raise AppError("Public IPv4 detection failed; supply --public-ip explicitly.")
