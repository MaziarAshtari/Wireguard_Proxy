"""Bounded, temporary sing-box validation and deployment health checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from typing import Callable, Iterator

from .core import AppError, Result, make_config, parse_wireguard, private_write
from .network import Proxy, RequestError, TEST_URL, exit_country, request


@dataclass(frozen=True)
class TestOptions:
    attempts: int = 3
    min_successes: int = 2
    timeout: float = 8.0
    concurrency: int = 2
    url: str = TEST_URL
    expected_status: int = 204

    def validate(self) -> None:
        if not 1 <= self.min_successes <= self.attempts <= 100:
            raise AppError("Require 1 <= min-successes <= test-attempts <= 100.")
        if not 0 < self.timeout <= 300 or not 1 <= self.concurrency <= 8:
            raise AppError("Timeout must be in (0, 300] and concurrency in [1, 8].")


def find_sing_box(binary: str = "sing-box") -> str:
    resolved = shutil.which(binary)
    if not resolved:
        raise AppError("sing-box is missing. Run 'sudo python3 -m wgproxy install' first.")
    try:
        output = subprocess.run([resolved, "version"], capture_output=True, timeout=10, check=True).stdout
        version = re.search(rb"sing-box version (\d+)\.(\d+)\.(\d+)", output)
        if not version or tuple(map(int, version.groups())) < (1, 12, 0):
            raise AppError("sing-box 1.12.0 or newer with WireGuard support is required.")
    except (OSError, subprocess.SubprocessError):
        raise AppError("Cannot run sing-box version.") from None
    return str(Path(resolved).resolve())


def check_config(binary: str, path: Path) -> None:
    try:
        subprocess.run([binary, "check", "-c", str(path)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        # sing-box diagnostics can quote entire JSON values, including secrets.
        raise AppError("sing-box check failed; verify binary version and configuration compatibility.") from None


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def check_ports(config: dict) -> None:
    """Hold all binds together to detect duplicate ports as well as existing listeners."""
    sockets = []
    try:
        for inbound in config["inbounds"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            # SO_REUSEADDR permits restart after TIME_WAIT, but not a live listener.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((inbound["listen"], inbound["listen_port"]))
            sock.listen(1)
    except OSError:
        raise AppError("A required TCP port is occupied or the listen IPv4 address is unavailable.") from None
    finally:
        for sock in sockets:
            sock.close()


@contextmanager
def temporary_instance(binary: str, config: dict, timeout: float,
                       cancel: threading.Event) -> Iterator[int]:
    process = None
    with tempfile.TemporaryDirectory(prefix="wgproxy-") as directory:
        path = Path(directory) / "config.json"
        private_write(path, json.dumps(config))
        check_config(binary, path)
        port = config["inbounds"][0]["listen_port"]
        try:
            environment = dict(os.environ, GOMEMLIMIT="96MiB", GOGC="50")
            process = subprocess.Popen([binary, "run", "-c", str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       env=environment)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if cancel.is_set():
                    raise AppError("Validation was interrupted.")
                if process.poll() is not None:
                    raise AppError("Temporary sing-box instance exited.")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    cancel.wait(0.05)
            else:
                raise AppError("Temporary sing-box startup timed out.")
            yield port
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def validate_one(path: Path, binary: str, options: TestOptions, dns_server: str,
                 cancel: threading.Event) -> Result:
    result = Result(path.name)
    try:
        result.wireguard = parse_wireguard(path)
    except AppError:
        result.status = "invalid"
        return result
    # Each process owns one tunnel and one authenticated loopback-only mixed inbound.
    import secrets
    password = secrets.token_urlsafe(32)
    config = make_config([(result.wireguard, free_port())], "127.0.0.1", "validation", password, dns_server)
    try:
        with temporary_instance(binary, config, options.timeout, cancel) as port:
            proxy = Proxy("127.0.0.1", port, "validation", password)
            successes, samples = 0, []
            for _ in range(options.attempts):
                if cancel.is_set():
                    raise AppError("Validation was interrupted.")
                pair = []
                for protocol in ("socks5", "http"):
                    try:
                        status, _, latency = request(proxy, protocol, options.url, options.timeout)
                        if status == options.expected_status:
                            pair.append(latency)
                    except RequestError:
                        pass
                if len(pair) == 2:
                    successes += 1
                    samples.extend(pair)
            if successes >= options.min_successes:
                result.status = "passed"
                result.latency_ms = statistics.median(samples)
                result.country = exit_country(proxy, options.timeout)
    except AppError:
        result.status = "start_failed"
    return result


def validate_files(paths: list[Path], binary: str, options: TestOptions, dns_server: str,
                   progress: Callable[[Result], None] | None = None) -> list[Result]:
    options.validate()
    results, cancel = [], threading.Event()
    executor = ThreadPoolExecutor(max_workers=options.concurrency)
    try:
        # At most one batch of futures and processes exists, even for large folders.
        for offset in range(0, len(paths), options.concurrency):
            batch = [executor.submit(validate_one, path, binary, options, dns_server, cancel)
                     for path in paths[offset:offset + options.concurrency]]
            for future in batch:
                result = future.result()
                results.append(result)
                if progress:
                    progress(result)
    finally:
        cancel.set()
        executor.shutdown(wait=True, cancel_futures=True)
    return results


def select_best(results: list[Result], start_port: int, maximum: int) -> list[Result]:
    working = sorted((result for result in results if result.status == "passed"),
                     key=lambda result: (result.latency_ms, result.filename))
    selected = working[:maximum] if maximum else working
    if selected and not 1 <= start_port <= 65536 - len(selected):
        raise AppError("The selected proxy port range exceeds 1..65535.")
    for result in working:
        result.status = "not_selected"
    for offset, result in enumerate(selected):
        result.status, result.port = "selected", start_port + offset
    return selected


def health_check(config: dict, options: TestOptions,
                 host: str | None = None) -> tuple[list[tuple[int, bool, bool]], dict[str, int]]:
    options.validate()
    proxies = []
    for inbound in config["inbounds"]:
        user = inbound["users"][0]
        address = host or ("127.0.0.1" if inbound["listen"] == "0.0.0.0" else inbound["listen"])
        proxies.append(Proxy(address, inbound["listen_port"], user["username"], user["password"]))

    def test(proxy: Proxy) -> tuple[int, bool, bool]:
        passed = []
        for protocol in ("socks5", "http"):
            successes = 0
            for _ in range(options.attempts):
                try:
                    status, _, _ = request(proxy, protocol, options.url, options.timeout)
                    successes += status == options.expected_status
                except RequestError:
                    pass
            passed.append(successes >= options.min_successes)
        return proxy.port, passed[0], passed[1]

    rows = []
    with ThreadPoolExecutor(max_workers=options.concurrency) as executor:
        for offset in range(0, len(proxies), options.concurrency):
            rows.extend(executor.map(test, proxies[offset:offset + options.concurrency]))
    counts = {"socks5_ok": sum(row[1] for row in rows),
              "http_ok": sum(row[2] for row in rows),
              "ok": sum(row[1] and row[2] for row in rows)}
    return rows, counts
