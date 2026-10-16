"""Bounded, temporary sing-box validation and deployment health checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from typing import Callable, Iterator
from urllib.parse import urlsplit

from .core import AppError, Result, make_config, parse_wireguard, private_write
from .network import Proxy, RequestError, TEST_URL, exit_country, request


@dataclass(frozen=True)
class TestOptions:
    attempts: int = 3
    min_successes: int = 2
    timeout: float = 8.0
    concurrency: int = 32
    url: str = TEST_URL
    expected_status: int = 204
    batch_size: int = 50

    def validate(self) -> None:
        if not 1 <= self.min_successes <= self.attempts <= 100:
            raise AppError("Require 1 <= MIN_SUCCESSES (--min-successes) <= TEST_ATTEMPTS (--test-attempts) <= 100.")
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 300:
            raise AppError("TEST_TIMEOUT / --test-timeout must be in (0, 300] seconds.")
        if not 1 <= self.concurrency <= 128:
            raise AppError("TEST_CONCURRENCY / --test-concurrency must be in 1..128.")
        if not 1 <= self.batch_size <= 200:
            raise AppError("BATCH_SIZE / --batch-size must be in 1..200.")
        if not 100 <= self.expected_status <= 599:
            raise AppError("Expected HTTP status must be in 100..599.")
        try:
            target = urlsplit(self.url)
            if (target.scheme not in ("http", "https") or not target.hostname
                    or target.username is not None or target.password is not None
                    or ":" in target.hostname or any(ord(c) < 33 or ord(c) == 127 for c in self.url)
                    or (target.port is not None and not 1 <= target.port <= 65535)):
                raise ValueError
        except ValueError:
            raise AppError("TEST_URL / --test-url must be HTTP(S), with a hostname or IPv4 and no credentials.") from None


class InstanceStartError(AppError):
    """A batch could not start; splitting it may isolate an incompatible tunnel."""


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
    return free_ports(1)[0]


def free_ports(count: int) -> list[int]:
    """Reserve together so a batch never receives duplicate ephemeral ports."""
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


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
        try:
            check_config(binary, path)
        except AppError:
            raise InstanceStartError("Temporary sing-box configuration check failed.") from None
        ports = [inbound["listen_port"] for inbound in config["inbounds"]]
        try:
            environment = dict(os.environ, GOMEMLIMIT="192MiB", GOGC="50")
            try:
                process = subprocess.Popen([binary, "run", "-c", str(path)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           env=environment)
            except OSError:
                raise InstanceStartError("Cannot start temporary sing-box instance.") from None
            deadline = time.monotonic() + timeout
            pending = set(ports)
            while time.monotonic() < deadline:
                if cancel.is_set():
                    raise AppError("Validation was interrupted.")
                if process.poll() is not None:
                    raise InstanceStartError("Temporary sing-box instance exited.")
                for port in tuple(pending):
                    if cancel.is_set():
                        raise AppError("Validation was interrupted.")
                    if time.monotonic() >= deadline:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            pending.remove(port)
                    except OSError:
                        pass
                if not pending and process.poll() is None:
                    break
                cancel.wait(0.05)
            else:
                raise InstanceStartError("Temporary sing-box startup timed out.")
            yield ports[0]
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def _parse_file(path: Path) -> Result:
    result = Result(path.name)
    try:
        result.wireguard = parse_wireguard(path)
    except AppError:
        result.status = "invalid"
    return result


def _check_tunnel(result: Result, proxy: Proxy, options: TestOptions,
                  cancel: threading.Event) -> Result:
    successes, samples = 0, []
    for _ in range(options.attempts):
        pair = []
        for protocol in ("socks5", "http"):
            if cancel.is_set():
                raise AppError("Validation was interrupted.")
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
        if cancel.is_set():
            raise AppError("Validation was interrupted.")
        result.country = exit_country(proxy, options.timeout)
        result.latency_ms = statistics.median(samples)
        result.status = "passed"
    return result


def _validate_batch(batch: list[Result], binary: str, options: TestOptions,
                    dns_server: str, cancel: threading.Event, executor: ThreadPoolExecutor,
                    progress: Callable[[Result], None]) -> None:
    if not batch:
        return
    if cancel.is_set():
        raise AppError("Validation was interrupted.")
    ports = free_ports(len(batch))
    password = secrets.token_urlsafe(32)
    config = make_config([(result.wireguard, port) for result, port in zip(batch, ports)],
                         "127.0.0.1", "validation", password, dns_server)
    try:
        with temporary_instance(binary, config, options.timeout, cancel):
            futures = []
            try:
                for result, port in zip(batch, ports):
                    futures.append(executor.submit(_check_tunnel, result,
                                                   Proxy("127.0.0.1", port, "validation", password), options, cancel))
                for future in as_completed(futures):
                    progress(future.result())
            except BaseException:
                # Drain workers before stopping the process or removing its private config.
                cancel.set()
                for future in futures:
                    future.cancel()
                for future in futures:
                    if not future.cancelled():
                        try:
                            future.result()
                        except BaseException:
                            pass
                raise
    except InstanceStartError:
        if cancel.is_set():
            raise AppError("Validation was interrupted.") from None
        # The parent process has been stopped before either child is started.
        if len(batch) == 1:
            batch[0].status = "start_failed"
            progress(batch[0])
        else:
            middle = len(batch) // 2
            _validate_batch(batch[:middle], binary, options, dns_server, cancel, executor, progress)
            _validate_batch(batch[middle:], binary, options, dns_server, cancel, executor, progress)


def validate_one(path: Path, binary: str, options: TestOptions, dns_server: str,
                 cancel: threading.Event) -> Result:
    options.validate()
    result = _parse_file(path)
    if result.status == "invalid":
        return result
    with ThreadPoolExecutor(max_workers=1) as executor:
        _validate_batch([result], binary, options, dns_server, cancel, executor, lambda result: None)
    return result


def validate_files(paths: list[Path], binary: str, options: TestOptions, dns_server: str,
                   progress: Callable[[Result], None] | None = None) -> list[Result]:
    options.validate()
    results, cancel = [], threading.Event()
    executor = ThreadPoolExecutor(max_workers=options.concurrency)
    try:
        # Bound parsing, queued checks, and endpoint memory to one batch at a time.
        for offset in range(0, len(paths), options.batch_size):
            batch = list(executor.map(_parse_file, paths[offset:offset + options.batch_size]))
            results.extend(batch)
            for result in batch:
                if result.status == "invalid" and progress:
                    progress(result)
            _validate_batch([result for result in batch if result.status != "invalid"],
                            binary, options, dns_server, cancel, executor, progress or (lambda result: None))
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
