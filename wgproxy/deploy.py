"""Verified sing-box installation and Ubuntu systemd deployment."""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import urllib.request
from typing import Callable

from .core import AppError, WireGuard, credentials, ipv4, make_config, private_write
from .validation import check_config, check_ports, find_sing_box

SERVICE = "sing-box-wgproxy.service"
CONFIG_PATH = Path("/etc/sing-box/wgproxy.json")
UNIT_PATH = Path("/etc/systemd/system") / SERVICE


def require_root() -> None:
    if os.geteuid() != 0:
        raise AppError("This command requires root; run it with sudo.")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise AppError("Deployment supports Linux x86_64 only.")


def _run(command: list[str], timeout: float = 90) -> None:
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError):
        raise AppError(f"System command failed: {Path(command[0]).name}.") from None


def _download(url: str, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise AppError("Download URL must use HTTPS.")
    # Never use ambient HTTP_PROXY/HTTPS_PROXY for privileged downloads.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "wgproxy/1"}), timeout=30) as response:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise AppError("Download exceeds the size limit.")
            return body
    except (OSError, ValueError, http.client.HTTPException):
        raise AppError("HTTPS download failed; check network access and GitHub API rate limits.") from None


def install_sing_box(binary: str = "sing-box", version: str | None = None) -> str:
    require_root()
    existing = shutil.which(binary)
    if existing:
        return find_sing_box(existing)
    if binary != "sing-box":
        raise AppError("The specified sing-box binary does not exist.")
    if version is not None and not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise AppError("sing-box version must be a stable version such as 1.14.3.")
    suffix = f"tags/v{version}" if version else "latest"
    try:
        release = json.loads(_download(f"https://api.github.com/repos/SagerNet/sing-box/releases/{suffix}", 4 * 1024 * 1024))
        tag = release["tag_name"]
        if release.get("prerelease") or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            raise AppError("A stable sing-box release is required.")
        name = f"sing-box-{tag[1:]}-linux-amd64.tar.gz"
        asset = next(asset for asset in release["assets"] if asset["name"] == name)
        digest = asset.get("digest", "")
        if not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest):
            raise AppError("GitHub did not provide a SHA-256 asset digest; installation stopped.")
        url = asset["browser_download_url"]
        if url != f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{name}":
            raise AppError("Unexpected release download URL.")
        archive_bytes = _download(url, 100 * 1024 * 1024)
        if hashlib.sha256(archive_bytes).hexdigest().lower() != digest[7:].lower():
            raise AppError("sing-box archive SHA-256 verification failed.")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            member = archive.getmember(f"sing-box-{tag[1:]}-linux-amd64/sing-box")
            if not member.isfile() or member.size > 200 * 1024 * 1024:
                raise AppError("Invalid sing-box archive member.")
            with archive.extractfile(member) as source:
                executable = source.read()
        target = Path("/usr/local/bin/sing-box")
        # Validate the binary before replacing the installed path.
        with tempfile.TemporaryDirectory(prefix="wgproxy-install-") as temporary:
            candidate = Path(temporary) / "sing-box"
            private_write(candidate, executable, 0o700)
            find_sing_box(str(candidate))
            private_write(target, executable, 0o755)
        return find_sing_box(str(target))
    except (KeyError, StopIteration, TypeError, ValueError, tarfile.TarError):
        raise AppError("Cannot read the sing-box release metadata or archive.") from None


def create_swap(path: Path = Path("/swapfile-wgproxy")) -> bool:
    require_root()
    if len(Path("/proc/swaps").read_text().splitlines()) > 1:
        return False
    if path.exists() or path.is_symlink():
        raise AppError("Swap path already exists; refusing to overwrite it.")
    if shutil.disk_usage(path.parent).free < 3 * 1024 ** 3:
        raise AppError("At least 3 GiB of free disk space is required to create swap.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    active = False
    try:
        # posix_fallocate produces an allocated, non-sparse file on Ubuntu ext4/xfs.
        try:
            os.posix_fallocate(fd, 0, 2 * 1024 ** 3)
        finally:
            os.close(fd)
        _run(["mkswap", str(path)])
        _run(["swapon", str(path)])
        active = True
        fstab = Path("/etc/fstab")
        content = fstab.read_text()
        entry = f"{path} none swap sw 0 0"
        if not any(line.split() and line.split()[0] == str(path) for line in content.splitlines()
                   if not line.lstrip().startswith("#")):
            private_write(fstab, content.rstrip() + "\n" + entry + "\n", fstab.stat().st_mode & 0o777)
        return True
    finally:
        if not active:
            path.unlink(missing_ok=True)


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        inbounds = config["inbounds"]
        if not isinstance(inbounds, list) or not inbounds:
            raise ValueError
        ports, tags = set(), set()
        for inbound in inbounds:
            if inbound["type"] != "mixed" or len(inbound["users"]) != 1:
                raise ValueError
            ipv4(inbound["listen"])
            port = inbound["listen_port"]
            if type(port) is not int or not 1 <= port <= 65535 or port in ports:
                raise ValueError
            ports.add(port)
            user = inbound["users"][0]
            credentials(user["username"], user["password"])
            tag = inbound["tag"]
            if not isinstance(tag, str) or tag in tags:
                raise ValueError
            tags.add(tag)
        # Only accept this project's generated topology, including tunnel-specific DNS.
        # This also prevents a hand-edited export from silently adding direct fallback.
        endpoints = config["endpoints"]
        servers = config["dns"]["servers"]
        if len(endpoints) != len(inbounds) or len(servers) != len(inbounds):
            raise ValueError
        items = []
        for endpoint, inbound in zip(endpoints, inbounds):
            peer = endpoint["peers"][0]
            wg = WireGuard("", endpoint["private_key"], tuple(endpoint["address"]),
                           peer["public_key"], peer.get("pre_shared_key", ""),
                           peer["address"], peer["port"], peer["persistent_keepalive_interval"])
            items.append((wg, inbound["listen_port"]))
        first = inbounds[0]
        user = first["users"][0]
        expected = make_config(items, first["listen"], user["username"], user["password"], servers[0]["server"])
        if config != expected:
            raise ValueError
        return config
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise AppError("Cannot read a valid generated proxy configuration; rebuild it with this project.") from None


def unit_text(binary: str) -> str:
    # systemd interprets quotes, %, and environment expansions in ExecStart.
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", binary):
        raise AppError("The sing-box executable path contains unsupported characters.")
    return f"""[Unit]
Description=Authenticated WireGuard mixed proxies
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=root
UMask=0077
ExecStartPre={binary} check -c {CONFIG_PATH}
ExecStart={binary} run -c {CONFIG_PATH}
Restart=on-failure
RestartSec=5
TasksMax=infinity
LimitNOFILE=65535
Environment=GOMEMLIMIT=384MiB
Environment=GOGC=50
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""


def deploy_config(binary: str, source: Path, swap: bool = False,
                  verify: Callable[[dict], None] | None = None) -> None:
    require_root()
    config = load_config(source)
    # Disable sing-box logs even if an existing config was supplied for deployment.
    config["log"] = {"disabled": True}
    unit = unit_text(binary)
    with tempfile.TemporaryDirectory(prefix="wgproxy-deploy-") as temporary:
        candidate = Path(temporary) / "config.json"
        private_write(candidate, json.dumps(config, indent=2) + "\n")
        check_config(binary, candidate)
        if swap:
            create_swap()
        was_active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=15).returncode == 0
        old_config = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
        old_unit = UNIT_PATH.read_bytes() if UNIT_PATH.exists() else None
        if was_active:
            _run(["systemctl", "stop", SERVICE])
        changed = False
        try:
            check_ports(config)
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            private_write(CONFIG_PATH, candidate.read_bytes())
            changed = True
            # systemd unit files are public metadata; all secret-bearing outputs are 0600.
            private_write(UNIT_PATH, unit, 0o644)
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "enable", SERVICE])
            _run(["systemctl", "restart", SERVICE])
            _run(["systemctl", "is-active", "--quiet", SERVICE], timeout=15)
            # A simple service can report active before its listeners are ready.
            import time
            deadline = time.monotonic() + 10
            while True:
                ready = True
                for inbound in config["inbounds"]:
                    host = "127.0.0.1" if inbound["listen"] == "0.0.0.0" else inbound["listen"]
                    try:
                        with socket.create_connection((host, inbound["listen_port"]), timeout=0.1):
                            pass
                    except OSError:
                        ready = False
                        break
                if ready:
                    break
                if time.monotonic() >= deadline:
                    raise AppError("The deployed proxy listeners did not become ready.")
                time.sleep(0.1)
            # The simple workflow includes reachability in the rollback boundary.
            if verify is not None:
                verify(config)
        except BaseException:
            # Restore a previously working deployment after bind/start failures.
            if changed:
                _run(["systemctl", "stop", SERVICE])
                if old_config is None:
                    CONFIG_PATH.unlink(missing_ok=True)
                else:
                    private_write(CONFIG_PATH, old_config)
                if old_unit is None:
                    _run(["systemctl", "disable", SERVICE])
                    UNIT_PATH.unlink(missing_ok=True)
                else:
                    private_write(UNIT_PATH, old_unit, 0o644)
                _run(["systemctl", "daemon-reload"])
            if was_active:
                _run(["systemctl", "start", SERVICE])
            raise
