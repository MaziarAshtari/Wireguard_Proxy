"""Literal .env settings and persistent private credentials; no shell evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat

from .core import AppError, credentials, ipv4, private_write
from .network import TEST_URL
from .validation import TestOptions

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    config_dir: Path = Path("configs")
    output_dir: Path = Path("output")
    start_port: int = 10000
    listen: str = "0.0.0.0"
    public_ip: str = ""
    max_proxies: int = 20
    username: str = field(default="proxy", repr=False)
    password: str = field(default="", repr=False)
    test_attempts: int = 3
    min_successes: int = 2
    test_timeout: float = 8.0
    batch_size: int = 50
    test_concurrency: int = 32
    dns_server: str = "1.1.1.1"
    test_url: str = TEST_URL
    create_swap: bool = False
    sing_box_version: str = ""

    def validate(self) -> None:
        if not 1 <= self.start_port <= 65535:
            raise AppError("START_PORT / --start-port must be in 1..65535.")
        if not 0 <= self.max_proxies <= 65535:
            raise AppError("MAX_PROXIES / --max-proxies must be in 0..65535 (0 keeps all).")
        for name, value in (("LISTEN", self.listen), ("DNS_SERVER", self.dns_server),
                            ("PUBLIC_IP", self.public_ip)):
            if name == "PUBLIC_IP" and not value:
                continue
            try:
                ipv4(value)
            except AppError:
                raise AppError(f"{name} must be an IPv4 address.") from None
        try:
            credentials(self.username, self.password or "generated")
        except AppError:
            raise AppError("USERNAME and PASSWORD must each contain 1..255 UTF-8 bytes with no colons or control characters; PASSWORD may be empty to generate it.") from None
        TestOptions(self.test_attempts, self.min_successes, self.test_timeout,
                    self.test_concurrency, self.test_url, batch_size=self.batch_size).validate()
        if self.sing_box_version:
            if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.sing_box_version)
                    or tuple(map(int, self.sing_box_version.split("."))) < (1, 12, 0)):
                raise AppError("SING_BOX_VERSION must be empty (latest stable) or a stable version at least 1.12.0.")


def parse_dotenv(content: str) -> dict[str, str]:
    """KEY=VALUE with literal quotes and comments; never expand variables or commands.

    A # starts an unquoted comment only at the start or after whitespace. Double
    quotes allow escaped double quotes and backslashes; single quotes are literal.
    Multiline values, duplicate keys, and unknown settings are rejected.
    """
    values = {}
    known = {name.upper() for name in Settings.__dataclass_fields__}
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        key, raw = key.strip(), raw.strip()
        error = f"Invalid .env syntax on line {number}; use KEY=VALUE with optional quotes and comments."
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise AppError(error)
        if key not in known:
            raise AppError(f"Unknown .env setting on line {number}; see .env.example.")
        if key in values:
            raise AppError(f"Duplicate .env setting on line {number}.")
        if raw.startswith(("'", '"')):
            quote, index, characters = raw[0], 1, []
            while index < len(raw) and raw[index] != quote:
                if quote == '"' and raw[index] == "\\" and index + 1 < len(raw) and raw[index + 1] in ('"', "\\"):
                    index += 1
                characters.append(raw[index])
                index += 1
            if index == len(raw) or (raw[index + 1:].strip() and not raw[index + 1:].lstrip().startswith("#")):
                raise AppError(error)
            value = "".join(characters)
        else:
            value = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].rstrip()
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise AppError(error)
        values[key] = value
    return values


def ensure_dotenv(root: Path) -> bool:
    """Return False after bootstrapping; the caller must stop for user review."""
    path = root / ".env"
    if path.is_symlink():
        raise AppError(".env must be a regular file, not a symbolic link.")
    if path.exists():
        return True
    try:
        private_write(path, (root / ".env.example").read_bytes())
    except OSError:
        raise AppError("Cannot create .env from .env.example; check project files and permissions.") from None
    print("Created .env with permissions 600. Review its settings, copy .conf files into CONFIG_DIR, then run the command again.")
    return False


def load_settings(root: Path = PROJECT_ROOT) -> Settings | None:
    path = root / ".env"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise AppError("Cannot open .env; use a readable regular file, not a symbolic link.") from None
    try:
        with os.fdopen(fd, "r", encoding="utf-8-sig") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise AppError(".env must be a regular file.")
            os.fchmod(source.fileno(), 0o600)
            content = source.read(65537)
            if len(content) > 65536:
                raise AppError(".env must be at most 64 KiB.")
    except (OSError, UnicodeError):
        raise AppError("Cannot read .env as private UTF-8 text; check ownership and permissions.") from None
    raw = parse_dotenv(content)
    converted = {}
    for key, value in raw.items():
        name = key.lower()
        default = getattr(Settings(), name)
        try:
            if isinstance(default, Path):
                if not value:
                    raise ValueError
                converted[name] = Path(value)
            elif isinstance(default, bool):
                if value.lower() not in ("true", "false", "yes", "no", "1", "0", "on", "off"):
                    raise ValueError
                converted[name] = value.lower() in ("true", "yes", "1", "on")
            elif isinstance(default, int):
                if not re.fullmatch(r"[+-]?[0-9]+", value):
                    raise ValueError
                converted[name] = int(value)
            elif isinstance(default, float):
                converted[name] = float(value)
            else:
                converted[name] = value
        except ValueError:
            kind = "a nonempty path" if isinstance(default, Path) else "true or false" if isinstance(default, bool) else "a number"
            raise AppError(f"{key} must be {kind}.") from None
    settings = Settings(**converted)
    settings.validate()
    # Relative .env paths always refer to the project, independent of cwd/sudo.
    from dataclasses import replace
    return replace(settings, config_dir=root / settings.config_dir, output_dir=root / settings.output_dir)


def persistent_password(path: Path) -> str:
    """Create once under a file lock, including concurrent builds to different dirs."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as output:
            if not stat.S_ISREG(os.fstat(output.fileno()).st_mode):
                raise AppError("The persistent password must be a regular private file.")
            os.fchmod(output.fileno(), 0o600)
            fcntl.flock(output, fcntl.LOCK_EX)
            password = output.read(1024).rstrip("\r\n")
            if not password:
                if os.fstat(output.fileno()).st_size:
                    raise AppError("The persistent password file is invalid; restore it from a backup.")
                password = secrets.token_urlsafe(32)
                output.write(password + "\n")
                output.flush()
                os.fsync(output.fileno())
            credentials("proxy", password)
            return password
    except (OSError, UnicodeError):
        raise AppError("Cannot read or create the private persistent password file; check ownership and permissions.") from None
