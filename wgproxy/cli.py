"""Command-line workflows. Diagnostics deliberately omit external error text."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import secrets
import sys

from . import __version__
from .core import AppError, credentials, ipv4, make_config, private_write, report_text, write_outputs
from .deploy import CONFIG_PATH, SERVICE, create_swap, deploy_config, install_sing_box, load_config
from .network import TEST_URL, public_ipv4
from .validation import TestOptions, check_config, find_sing_box, health_check, select_best, validate_files


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal errors can echo a password supplied in the wrong position.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command-line arguments; see --help.\n")


def _test_arguments(parser: argparse.ArgumentParser, health: bool = False) -> None:
    parser.add_argument("--test-attempts", type=int, default=1 if health else 3, metavar="M")
    parser.add_argument("--min-successes", type=int, default=1 if health else 2, metavar="N")
    parser.add_argument("--test-timeout", type=float, default=8, metavar="SECONDS",
                        help="deadline per HTTP request, including proxy handshake (default: 8)")
    parser.add_argument("--test-concurrency", type=int, default=2, metavar="COUNT",
                        help="parallel tunnels/proxies, 1..8 (default: 2)")
    parser.add_argument("--test-url", default=TEST_URL)
    parser.add_argument("--expected-status", type=int, default=204)


def _build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--start-port", type=int, default=10000)
    parser.add_argument("--listen", default="0.0.0.0", help="listen IPv4 (default: 0.0.0.0)")
    parser.add_argument("--max-proxies", type=int, default=0, help="keep the fastest N; 0 keeps all (default)")
    parser.add_argument("--username", default="proxy")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password", help="password; prefer a password file to avoid shell history/process listings")
    group.add_argument("--password-file", type=Path, help="read a password from a private UTF-8 file")
    parser.add_argument("--public-ip", help="override automatic public IPv4 detection")
    parser.add_argument("--dns-server", default="1.1.1.1", help="IPv4 DNS resolver reached through each tunnel")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    _test_arguments(parser)


def parser() -> argparse.ArgumentParser:
    root = SafeParser(description="Create authenticated, isolated WireGuard mixed proxies.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    install = commands.add_parser("install", help="install sing-box if missing (requires root)")
    install.add_argument("--sing-box", default="sing-box")
    install.add_argument("--sing-box-version", help="stable version to install if missing; default: latest")
    install.add_argument("--create-swap", action="store_true", help="create 2 GiB swap if no swap is active")
    build = commands.add_parser("build", help="validate WireGuard files and write private output files")
    build.add_argument("--config-dir", type=Path, required=True)
    build.add_argument("--sing-box", default="sing-box")
    _build_arguments(build)
    deploy = commands.add_parser("deploy", help="install, validate and deploy; or deploy an existing generated config")
    source = deploy.add_mutually_exclusive_group(required=True)
    source.add_argument("--config-dir", type=Path)
    source.add_argument("--config", type=Path, help="deploy an existing generated sing-box.json")
    deploy.add_argument("--sing-box", default="sing-box")
    deploy.add_argument("--sing-box-version")
    deploy.add_argument("--create-swap", action="store_true")
    _build_arguments(deploy)
    health = commands.add_parser("health-check", help="test SOCKS5 and HTTP for every deployed proxy")
    health.add_argument("--config", type=Path, default=CONFIG_PATH)
    health.add_argument("--host", help="override target IPv4; default: local listen address")
    _test_arguments(health, health=True)
    return root


def _options(args) -> TestOptions:
    options = TestOptions(args.test_attempts, args.min_successes, args.test_timeout,
                          args.test_concurrency, args.test_url, args.expected_status)
    options.validate()
    if not math.isfinite(args.test_timeout) or not 100 <= args.expected_status <= 599:
        raise AppError("Invalid request timeout or expected HTTP status.")
    from urllib.parse import urlsplit
    try:
        target = urlsplit(args.test_url)
        if target.scheme not in ("http", "https") or not target.hostname or target.username or target.password:
            raise ValueError
        if ":" in target.hostname or any(c in args.test_url for c in "\r\n"):
            raise ValueError
        if target.port is not None and not 1 <= target.port <= 65535:
            raise ValueError
    except ValueError:
        raise AppError("Test URL must be HTTP(S), with a hostname or IPv4 and no credentials.") from None
    return options


@contextmanager
def _output_lock(directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AppError("Another build is using this output directory.") from None
        yield
    finally:
        os.close(fd)


def build(args, binary: str) -> Path:
    options = _options(args)
    ipv4(args.listen)
    ipv4(args.dns_server)
    if not 1 <= args.start_port <= 65535 or args.max_proxies < 0:
        raise AppError("Start port must be in 1..65535 and max-proxies must be nonnegative.")
    password = args.password
    if args.password_file:
        try:
            if args.password_file.stat().st_mode & 0o077:
                raise AppError("Password file must have permissions 600 or stricter.")
            password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
        except (OSError, UnicodeError):
            raise AppError("Cannot read the private password file.") from None
    if password is None:
        password = secrets.token_urlsafe(32)
    credentials(args.username, password)
    if not args.config_dir.is_dir():
        raise AppError("The configuration folder does not exist.")
    paths = sorted(path for path in args.config_dir.iterdir() if path.is_file() and path.suffix.lower() == ".conf")
    if not paths:
        raise AppError("The configuration folder contains no .conf files.")
    address = ipv4(args.public_ip) if args.public_ip else public_ipv4(options.timeout)
    with _output_lock(args.output_dir):
        # Invalidate old exports first so a failed rebuild cannot redeploy stale proxies.
        for name in ("sing-box.json", "socks5.txt", "http.txt", "plain.txt", "report.csv"):
            (args.output_dir / name).unlink(missing_ok=True)
        print(f"Validating {len(paths)} configurations with concurrency {options.concurrency}.", flush=True)
        completed = 0

        def progress(result):
            nonlocal completed
            completed += 1
            print(f"Validated {completed}/{len(paths)}: {result.status}.", flush=True)

        results = validate_files(paths, binary, options, args.dns_server, progress)
        private_write(args.output_dir / "report.csv", report_text(results))
        selected = select_best(results, args.start_port, args.max_proxies)
        if not selected:
            raise AppError("No configurations passed validation. Only report.csv was written.")
        config = make_config([(result.wireguard, result.port) for result in selected],
                             args.listen, args.username, password, args.dns_server)
        # Check in a private staging file before publishing any final proxy exports.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="wgproxy-final-") as temporary:
            path = Path(temporary) / "config.json"
            private_write(path, json.dumps(config))
            check_config(binary, path)
        write_outputs(args.output_dir, config, address, results)
        print(f"Selected {len(selected)} proxies; TCP ports {selected[0].port}-{selected[-1].port}.")
        print("Private config, proxy lists, and report written to the output directory. Credentials are stored only in files.")
    return args.output_dir / "sing-box.json"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "install":
            install_sing_box(args.sing_box, args.sing_box_version)
            if args.create_swap:
                created = create_swap()
                print("Created 2 GiB swap." if created else "Active swap already exists; skipped.")
            print("sing-box is installed and compatible.")
        elif args.command == "build":
            build(args, find_sing_box(args.sing_box))
        elif args.command == "deploy":
            binary = install_sing_box(args.sing_box, args.sing_box_version)
            source = args.config if args.config else build(args, binary)
            deploy_config(binary, source, args.create_swap)
            print(f"Enabled and started {SERVICE}.")
        else:
            options = _options(args)
            if args.host:
                ipv4(args.host)
            rows, counts = health_check(load_config(args.config), options, args.host)
            for port, socks, http in rows:
                print(f"Port {port}: SOCKS5 {'OK' if socks else 'FAIL'}, HTTP {'OK' if http else 'FAIL'}")
            total = len(rows)
            print(f"SOCKS5: OK {counts['socks5_ok']}, FAIL {total - counts['socks5_ok']}")
            print(f"HTTP: OK {counts['http_ok']}, FAIL {total - counts['http_ok']}")
            print(f"Proxies: OK {counts['ok']}, FAIL {total - counts['ok']}")
            return 0 if counts["ok"] == total else 1
        return 0
    except AppError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; temporary validation processes have been stopped.", file=sys.stderr)
        return 130
    except Exception:
        # Tracebacks from parsers, subprocesses, and JSON can expose secret values.
        print("Error: operation failed; check paths, permissions, network access, and system services.", file=sys.stderr)
        return 1
