"""Command-line workflows. Diagnostics deliberately omit external error text."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sys
import time

from . import __version__
from .core import AppError, credentials, ipv4, make_config, private_write, report_text, write_outputs
from .deploy import CONFIG_PATH, SERVICE, create_swap, deploy_config, install_sing_box, load_config
from .network import public_ipv4
from .settings import PROJECT_ROOT, Settings, ensure_dotenv, load_settings, persistent_password
from .validation import TestOptions, check_config, find_sing_box, health_check, select_best, validate_files


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal errors can echo a password supplied in the wrong position.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command-line arguments; see --help.\n")


def _test_arguments(parser: argparse.ArgumentParser, health: bool = False,
                    settings: Settings | None = None) -> None:
    defaults = settings or Settings()
    parser.add_argument("--test-attempts", type=int, default=1 if health and not settings else defaults.test_attempts, metavar="M")
    parser.add_argument("--min-successes", type=int, default=1 if health and not settings else defaults.min_successes, metavar="N")
    parser.add_argument("--test-timeout", type=float, default=defaults.test_timeout, metavar="SECONDS",
                        help="deadline per HTTP request, including proxy handshake (default: 8)")
    parser.add_argument("--test-concurrency", type=int, default=defaults.test_concurrency, metavar="COUNT",
                        help="parallel tunnel checks, 1..128 (default: 32)")
    parser.add_argument("--test-url", default=defaults.test_url)
    parser.add_argument("--expected-status", type=int, default=204)


def _build_arguments(parser: argparse.ArgumentParser, settings: Settings | None = None) -> None:
    defaults = settings or Settings()
    parser.add_argument("--start-port", type=int, default=defaults.start_port)
    parser.add_argument("--listen", default=defaults.listen, help="listen IPv4 (default: 0.0.0.0)")
    parser.add_argument("--max-proxies", type=int, default=settings.max_proxies if settings else 0,
                        help="keep the fastest N; 0 keeps all; .env default: 20")
    parser.add_argument("--username", default=defaults.username)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password", help="password; prefer a password file to avoid shell history/process listings")
    group.add_argument("--password-file", type=Path, help="read a password from a private UTF-8 file")
    parser.add_argument("--public-ip", default=defaults.public_ip, help="override automatic public IPv4 detection")
    parser.add_argument("--dns-server", default=defaults.dns_server, help="IPv4 DNS resolver reached through each tunnel")
    parser.add_argument("--output-dir", type=Path, default=defaults.output_dir)
    parser.add_argument("--batch-size", type=int, default=defaults.batch_size,
                        help="tunnels per temporary sing-box process, 1..200 (default: 50)")
    _test_arguments(parser, settings=settings)


def parser(settings: Settings | None = None) -> argparse.ArgumentParser:
    root = SafeParser(description="Create authenticated, isolated WireGuard mixed proxies.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    install = commands.add_parser("install", help="install sing-box if missing (requires root)")
    install.add_argument("--sing-box", default="sing-box")
    install.add_argument("--sing-box-version", default=settings.sing_box_version or None if settings else None,
                         help="stable version to install if missing; default: latest")
    install.add_argument("--create-swap", action=argparse.BooleanOptionalAction,
                         default=settings.create_swap if settings else False, help="create 2 GiB swap if no swap is active")
    build = commands.add_parser("build", help="validate WireGuard files and write private output files")
    build.add_argument("--config-dir", type=Path, required=settings is None,
                       default=settings.config_dir if settings else None)
    build.add_argument("--sing-box", default="sing-box")
    _build_arguments(build, settings)
    for command, help_text in (("deploy", "install, validate and deploy; or deploy an existing generated config"),
                               ("run", "install, validate, build, deploy, and check proxy health")):
        deploy = commands.add_parser(command, help=help_text)
        source = deploy.add_mutually_exclusive_group(required=settings is None)
        source.add_argument("--config-dir", type=Path, default=settings.config_dir if settings else None)
        source.add_argument("--config", type=Path, help="deploy an existing generated sing-box.json")
        deploy.add_argument("--sing-box", default="sing-box")
        deploy.add_argument("--sing-box-version", default=settings.sing_box_version or None if settings else None)
        deploy.add_argument("--create-swap", action=argparse.BooleanOptionalAction,
                            default=settings.create_swap if settings else False)
        _build_arguments(deploy, settings)
    health = commands.add_parser("health-check", help="test SOCKS5 and HTTP for every deployed proxy")
    health.add_argument("--config", type=Path, default=CONFIG_PATH)
    health.add_argument("--host", help="override target IPv4; default: local listen address")
    _test_arguments(health, health=True, settings=settings)
    return root


def _options(args) -> TestOptions:
    options = TestOptions(args.test_attempts, args.min_successes, args.test_timeout,
                          args.test_concurrency, args.test_url, args.expected_status,
                          getattr(args, "batch_size", 50))
    options.validate()
    return options


def _validate_build_arguments(args) -> TestOptions:
    options = _options(args)
    Settings(start_port=args.start_port, listen=args.listen, public_ip=args.public_ip or "",
             max_proxies=args.max_proxies, username=args.username, password=args.password or "",
             dns_server=args.dns_server).validate()
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
    options = _validate_build_arguments(args)
    password = args.password
    if args.password_file:
        try:
            if args.password_file.stat().st_mode & 0o077:
                raise AppError("Password file must have permissions 600 or stricter.")
            password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
        except (OSError, UnicodeError):
            raise AppError("Cannot read the private password file.") from None
        credentials(args.username, password)
    if not args.config_dir.is_dir():
        raise AppError("The configuration folder does not exist.")
    paths = sorted(path for path in args.config_dir.iterdir() if path.is_file() and path.suffix.lower() == ".conf")
    if not paths:
        raise AppError("The configuration folder contains no .conf files.")
    address = ipv4(args.public_ip) if args.public_ip else public_ipv4(options.timeout)
    with _output_lock(args.output_dir):
        if not password:
            password = persistent_password(getattr(args, "password_store", args.output_dir / ".password"))
        credentials(args.username, password)
        # Invalidate old exports first so a failed rebuild cannot redeploy stale proxies.
        for name in ("sing-box.json", "socks5.txt", "http.txt", "plain.txt", "report.csv"):
            (args.output_dir / name).unlink(missing_ok=True)
        print(f"Validating {len(paths)} configurations; batch size {options.batch_size}, concurrency {options.concurrency}.", flush=True)
        completed = passed = 0
        started = time.monotonic()

        def progress(result):
            nonlocal completed, passed
            completed += 1
            passed += result.status == "passed"
            print(f"Validated {completed}/{len(paths)}, passed {passed} ({time.monotonic() - started:.1f}s).", flush=True)

        try:
            results = validate_files(paths, binary, options, args.dns_server, progress)
        finally:
            print(f"Validation elapsed time: {time.monotonic() - started:.1f}s.", flush=True)
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
        print("Private output files:")
        for name in ("sing-box.json", "socks5.txt", "http.txt", "plain.txt", "report.csv"):
            print(f"  {args.output_dir / name}")
    return args.output_dir / "sing-box.json"


def _print_health(config: dict, options: TestOptions, host: str | None = None) -> bool:
    rows, counts = health_check(config, options, host)
    for port, socks, http in rows:
        print(f"Port {port}: SOCKS5 {'OK' if socks else 'FAIL'}, HTTP {'OK' if http else 'FAIL'}")
    total = len(rows)
    print(f"SOCKS5: OK {counts['socks5_ok']}, FAIL {total - counts['socks5_ok']}")
    print(f"HTTP: OK {counts['http_ok']}, FAIL {total - counts['http_ok']}")
    print(f"Proxies: OK {counts['ok']}, FAIL {total - counts['ok']}")
    return bool(total) and counts["ok"] == total


def main(argv: list[str] | None = None, *, simple: bool = False,
         project_root: Path | None = None) -> int:
    try:
        root = project_root if project_root is not None else PROJECT_ROOT
        argv = list(sys.argv[1:] if argv is None else argv)
        if simple and not any(flag in argv for flag in ("--help", "-h", "--version")):
            if not ensure_dotenv(root):
                return 0
        settings = load_settings(root)
        if simple and (not argv or (argv[0].startswith("-") and argv[0] not in ("--help", "-h", "--version"))):
            argv.insert(0, "run")
        args = parser(settings).parse_args(argv)
        if args.command in ("build", "deploy", "run"):
            # Set password after parsing so --password-file always overrides .env.
            if args.password is None and not args.password_file and settings:
                args.password = settings.password or None
            if settings:
                args.password_store = root / ".wgproxy-password"
            if args.command == "build" or not args.config:
                _validate_build_arguments(args)
        if args.command in ("install", "deploy", "run") and args.sing_box_version:
            Settings(sing_box_version=args.sing_box_version).validate()
        if args.command == "install":
            install_sing_box(args.sing_box, args.sing_box_version)
            if args.create_swap:
                created = create_swap()
                print("Created 2 GiB swap." if created else "Active swap already exists; skipped.")
            print("sing-box is installed and compatible.")
        elif args.command == "build":
            build(args, find_sing_box(args.sing_box))
        elif args.command in ("deploy", "run"):
            options = _options(args)
            binary = install_sing_box(args.sing_box, args.sing_box_version)
            if args.create_swap:
                created = create_swap()
                print("Created 2 GiB swap." if created else "Active swap already exists; skipped.")
            source = args.config if args.config else build(args, binary)
            if args.command == "run":
                outcome = None
                config = load_config(source)

                def verify(candidate):
                    nonlocal outcome
                    print("Checking deployed proxy health.", flush=True)
                    outcome = _print_health(candidate, options)
                    if not outcome:
                        raise AppError("The deployed proxies failed the health check.")

                try:
                    deploy_config(binary, source, verify=verify)
                finally:
                    if outcome is not None:
                        ports = [item["listen_port"] for item in config["inbounds"]]
                        print(f"Summary: selected {len(ports)}; TCP ports {min(ports)}-{max(ports)}; health {'OK' if outcome else 'FAIL'}.")
                        print(f"Config: {source}")
                        print(f"Proxy lists and report: {source.parent}")
            else:
                deploy_config(binary, source)
            print(f"Enabled and started {SERVICE}.")
        else:
            options = _options(args)
            if args.host:
                ipv4(args.host)
            return 0 if _print_health(load_config(args.config), options, args.host) else 1
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
