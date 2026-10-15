"""WireGuard parsing, isolated sing-box configuration, and private files."""

from __future__ import annotations

import base64
import binascii
import configparser
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import tempfile
from dataclasses import dataclass, field
from urllib.parse import quote


class AppError(Exception):
    """An English diagnostic that is safe to display without credentials."""


def ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        raise AppError("An IPv4 address is required.") from None


def credentials(username: str, password: str) -> None:
    # Colons and line breaks would make the raw ip:port:user:pass format ambiguous.
    for value in (username, password):
        if not 1 <= len(value.encode("utf-8")) <= 255:
            raise AppError("Credentials must contain 1 to 255 UTF-8 bytes.")
        if ":" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise AppError("Credentials cannot contain colons or control characters.")


def private_write(path: Path, content: str | bytes, mode: int = 0o600) -> None:
    """Replace atomically; never follow a destination symlink or expose a partial file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".wgproxy-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(content.encode("utf-8") if isinstance(content, str) else content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class WireGuard:
    filename: str
    private_key: str = field(repr=False)
    addresses: tuple[str, ...]
    public_key: str = field(repr=False)
    preshared_key: str = field(repr=False)
    endpoint: str
    endpoint_port: int
    keepalive: int = 25


@dataclass
class Result:
    filename: str
    wireguard: WireGuard | None = field(default=None, repr=False)
    status: str = "failed"
    country: str = "UNKNOWN"
    latency_ms: float | None = None
    port: int | None = None


def _key(value: str) -> str:
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError
    except (ValueError, binascii.Error):
        raise AppError("Invalid WireGuard key; expected base64 encoding of 32 bytes.") from None
    return value


def parse_wireguard(path: Path) -> WireGuard:
    # ConfigParser rejects multiple Peer sections, intentionally: one tunnel per input.
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
    try:
        with path.open(encoding="utf-8-sig") as source:
            parser.read_file(source)
        if parser.defaults() or set(parser.sections()) != {"Interface", "Peer"}:
            raise AppError("Exactly one Interface and one Peer section are required.")
        interface, peer = parser["Interface"], parser["Peer"]
        addresses = tuple(dict.fromkeys(
            str(address) for part in interface["Address"].split(",")
            if (address := ipaddress.ip_interface(part.strip())).version == 4
        ))
        if not addresses:
            raise AppError("No IPv4 interface address found.")
        endpoint, separator, port_text = peer["Endpoint"].strip().rpartition(":")
        if not separator or not endpoint or ":" in endpoint:
            raise AppError("Endpoint must be an IPv4 address or hostname followed by a port.")
        endpoint_port = int(port_text)
        keepalive = int(peer.get("PersistentKeepalive", "25"))
        if not 1 <= endpoint_port <= 65535 or not 0 <= keepalive <= 65535:
            raise AppError("Invalid endpoint port or keepalive interval.")
        # Resolve endpoint hostnames once to avoid bootstrap DNS and routing loops.
        try:
            endpoint = str(ipaddress.IPv4Address(endpoint))
        except ipaddress.AddressValueError:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", endpoint):
                raise AppError("Invalid endpoint hostname.") from None
            endpoint = socket.getaddrinfo(endpoint, endpoint_port, socket.AF_INET,
                                          socket.SOCK_DGRAM)[0][4][0]
        return WireGuard(
            path.name, _key(interface["PrivateKey"].strip()), addresses,
            _key(peer["PublicKey"].strip()),
            _key(peer["PresharedKey"].strip()) if peer.get("PresharedKey", "").strip() else "",
            endpoint, endpoint_port, keepalive,
        )
    except AppError:
        raise
    except (OSError, UnicodeError, configparser.Error, KeyError, ValueError):
        # Parser errors can contain the full offending line, including private keys.
        raise AppError("Cannot parse WireGuard configuration or resolve its IPv4 endpoint.") from None


def make_config(items: list[tuple[WireGuard, int]], listen: str,
                username: str, password: str, dns_server: str = "1.1.1.1") -> dict:
    credentials(username, password)
    ipv4(listen)
    ipv4(dns_server)
    if not items:
        raise AppError("No validated proxies are available.")
    inbounds, endpoints, servers = [], [], []
    rules = [{"ip_version": 6, "action": "reject"}]
    for index, (wg, port) in enumerate(items):
        inbound, endpoint, dns = f"proxy-{index}", f"wg-{index}", f"dns-{index}"
        inbounds.append({
            "type": "mixed", "tag": inbound, "listen": listen, "listen_port": port,
            "users": [{"username": username, "password": password}],
        })
        peer = {"address": wg.endpoint, "port": wg.endpoint_port,
                "public_key": wg.public_key, "allowed_ips": ["0.0.0.0/0"],
                "persistent_keepalive_interval": wg.keepalive}
        if wg.preshared_key:
            peer["pre_shared_key"] = wg.preshared_key
        endpoints.append({
            "type": "wireguard", "tag": endpoint, "system": False, "mtu": 1280,
            "address": list(wg.addresses), "private_key": wg.private_key,
            "peers": [peer], "workers": 1,
            "domain_resolver": {"server": dns, "strategy": "ipv4_only"},
        })
        servers.append({"type": "udp", "tag": dns, "server": dns_server, "detour": endpoint})
        rules.extend([
            {"inbound": [inbound], "action": "resolve", "server": dns,
             "strategy": "ipv4_only", "disable_cache": True},
            {"inbound": [inbound], "action": "route", "outbound": endpoint},
        ])
    rules.append({"action": "reject"})
    return {
        "log": {"disabled": True},
        "dns": {"servers": servers, "strategy": "ipv4_only", "disable_cache": True},
        # A concrete final endpoint prevents sing-box from creating an implicit direct
        # outbound. The catch-all reject rule still rejects every unmatched connection.
        "inbounds": inbounds, "endpoints": endpoints,
        "route": {"rules": rules, "final": "wg-0"},
    }


def report_text(results: list[Result]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["file_name", "port", "country", "latency_ms", "status"])
    for result in results:
        writer.writerow([result.filename, result.port or "", result.country,
                         f"{result.latency_ms:.2f}" if result.latency_ms is not None else "",
                         result.status])
    return output.getvalue()


def write_outputs(directory: Path, config: dict, public_ip: str, results: list[Result]) -> None:
    ipv4(public_ip)
    # Publish config last. A failed validation run never leaves an old usable config.
    private_write(directory / "report.csv", report_text(results))
    for scheme in ("socks5", "http", "plain"):
        lines = []
        for inbound in config["inbounds"]:
            user = inbound["users"][0]
            port = inbound["listen_port"]
            if scheme == "plain":
                lines.append(f"{public_ip}:{port}:{user['username']}:{user['password']}")
            else:
                username, password = quote(user["username"], safe=""), quote(user["password"], safe="")
                lines.append(f"{scheme}://{username}:{password}@{public_ip}:{port}")
        private_write(directory / f"{scheme}.txt", "\n".join(lines) + ("\n" if lines else ""))
    private_write(directory / "sing-box.json", json.dumps(config, indent=2) + "\n")
