# WireGuard mixed proxies

A small Python 3 project with no third-party Python dependencies. It validates a folder of WireGuard files, keeps the fastest working tunnels, and runs authenticated SOCKS5 and HTTP on one TCP port per tunnel using sing-box. Designed for Ubuntu 24.04 x86_64, including servers with about 1 GiB RAM.

## Simple workflow

Use Ubuntu's Python 3.12 or newer. Run commands from this project directory; no pip installation is needed.

```bash
mkdir -p configs
chmod 700 configs
# Copy your WireGuard .conf files into configs/.
chmod 600 configs/*.conf

cp .env.example .env
chmod 600 .env
nano .env

sudo python3 run.py
```

The command installs sing-box if missing, optionally creates swap, validates every input, selects the fastest passing tunnels, writes private exports, deploys the systemd service, and checks every proxy through both protocols. It ends with the selected count, TCP port range, health OK/FAIL, and output paths. Failed service startup or a failed health check restores the previous deployment and returns a nonzero exit status.

If `.env` is missing, `run.py` copies the fully commented `.env.example` to `.env` with mode **600**, asks you to review it, and exits without installing or deploying anything. Run it again after editing. `.env`, `configs/`, `output/`, and the generated password file are ignored by Git.

All settings are in `.env`. Defaults are batches of **50** tunnels with **32** concurrent checks and at most **20** selected proxies, suitable as a starting point for a 1 GiB server. Use `BATCH_SIZE` and `TEST_CONCURRENCY` to tune validation; `MAX_PROXIES=0` selects all passing tunnels and needs more deployment memory. `CREATE_SWAP=true` enables optional 2 GiB swap before validation. Leave `PUBLIC_IP` empty to auto-detect the advertised server address, or set its IPv4 explicitly.

Leave `PASSWORD` empty to generate a strong password once in **`.wgproxy-password` (mode 600)**. Rebuilds reuse it, preserving credentials in existing client links. Keep this file with the project and back it up securely. An explicit `.env` password overrides it. Ports are still assigned by latency ranking, so rebuilds can change which tunnel serves a port.

The `.env` parser accepts `KEY=VALUE`, blank lines, `#` comments, and single/double quoted values. An unquoted `#` starts a comment at the start of a value or after whitespace; quote passwords containing such characters. Double quotes support escaped quotes and backslashes. Values are literal: shell commands, `$VARIABLE` expansion, and multiline values are never executed or expanded. Unknown/duplicate keys and invalid settings produce English errors without echoing values. Relative `.env` paths refer to the project directory, even when invoked from another directory. Process environment variables do not override `.env`.

Optional commands:

```bash
# Validate and build only; no root needed (sing-box must already be installed).
python3 run.py build

# Check the deployed config (normally root-readable), or a generated config.
sudo python3 run.py health-check
python3 run.py health-check --config output/sing-box.json

# Flags override .env defaults, including --no-create-swap.
sudo python3 run.py --max-proxies 10 --batch-size 25 --test-concurrency 16
```

The existing `python3 -m wgproxy` CLI remains available and also reads `.env` when present. Without `.env`, it keeps its explicit `--config-dir` workflow and selects all passing tunnels by default. Health checks without `.env` default to one attempt per protocol; with `.env` they use its attempt settings. Build-only commands never install software, create swap, or change systemd. Ensure the user running a build can read `.env` and write the output/password files; files created under sudo may require adjusting ownership first.

## Installation and advanced CLI

```bash
sudo apt-get update
sudo apt-get install -y python3 ca-certificates
python3 -m wgproxy --help

# Install separately if desired; optionally create 2 GiB swap.
sudo python3 -m wgproxy install --create-swap
```

The installer downloads the latest stable official Linux amd64 release from GitHub over HTTPS and verifies its SHA-256 against the release API asset digest. It installs to `/usr/local/bin/sing-box` without executing a remote installation script. Use `--sing-box-version 1.14.3` to select a release when installing a missing binary. An existing binary is checked and reused, never upgraded automatically. Configuration uses the WireGuard endpoint format and typed DNS servers supported by sing-box **1.12.0+**, with a build that includes WireGuard support. Integration tested with **1.14.3**.

## Build and deploy

```bash
python3 -m wgproxy build \
  --config-dir ./configs \
  --start-port 10000 \
  --listen 0.0.0.0 \
  --max-proxies 20 \
  --username proxy \
  --test-attempts 3 \
  --min-successes 2 \
  --test-timeout 8 \
  --batch-size 50 \
  --test-concurrency 32 \
  --output-dir ./output

sudo python3 -m wgproxy deploy --config ./output/sing-box.json
sudo python3 -m wgproxy health-check
```

Generated passwords are cryptographically random 32-byte URL-safe tokens, stored in the config and proxy lists and never printed. With `.env`, the persistent copy is `.wgproxy-password`; the CLI without `.env` uses `OUTPUT_DIR/.password`. Neither file is removed by a rebuild. To supply your own, use `.env` or a mode-600 UTF-8 file with `--password-file ./proxy-password.txt`, which overrides `.env`. A trailing newline is removed. `--password` is also supported, but its value can appear in shell history and process listings. Credentials must contain 1–255 UTF-8 bytes, with no colons or control characters, so all export formats stay unambiguous.

A single deploy command can install sing-box, validate the inputs, write the outputs, and start the service:

```bash
sudo python3 -m wgproxy deploy \
  --config-dir ./configs \
  --output-dir ./output \
  --start-port 10000 \
  --max-proxies 20 \
  --username proxy \
  --create-swap
```

`--max-proxies 0` keeps all passing tunnels; all inputs are tested before ranking. Selected tunnels receive consecutive ports in median-latency order. Equal latencies are ordered by filename. The selected range must fit in 1–65535. `--listen` accepts a local IPv4 address; `0.0.0.0` listens on all IPv4 interfaces. Public IPv4 is detected directly over HTTPS using Cloudflare's IPv4 trace endpoints. Use `--public-ip YOUR_SERVER_IPV4` if detection is blocked or you need a specific NAT address. The advertised public IP is independent of the listen address and each tunnel's exit IP.

**Open the selected TCP port range in your cloud firewall, restricted to trusted source IPs.** Apply the same restriction in the host firewall if enabled. For example, for ports 10000–10019, replace the documentation IP below with your trusted client IP:

```bash
sudo ufw allow from 198.51.100.10 to any port 10000:10019 proto tcp
```

Clients need TCP access to the mixed ports; the server needs outbound UDP to the WireGuard peer endpoints. SOCKS5 username/password and HTTP Basic authentication do not encrypt the client-to-proxy connection. Use a trusted private network or an encrypted transport when that connection crosses an untrusted network. The server-to-exit connection runs through WireGuard.

## Validation and routing

- Each input must have exactly one `[Interface]` and one `[Peer]`. The parser reads `PrivateKey`, IPv4 `Address` entries, `PublicKey`, optional `PresharedKey`, `Endpoint`, and optional `PersistentKeepalive` (default 25 seconds). Keys must decode to 32 bytes. IPv6 interface addresses are discarded; IPv6-only inputs and IPv6 endpoints are rejected. Endpoint hostnames are resolved to IPv4 once during parsing using the host resolver. Regenerate to refresh their addresses.
- Each temporary sing-box process contains up to **50** userspace WireGuard endpoints by default. Each endpoint has its own randomly authenticated `mixed` inbound on a unique ephemeral `127.0.0.1` port and its own route and DNS detour. Only one validation process runs at a time; a thread pool checks up to **32** tunnels concurrently. `BATCH_SIZE` / `--batch-size` accepts 1–200; `TEST_CONCURRENCY` / `--test-concurrency` accepts 1–128. Parsing also uses the bounded pool. A batch that fails configuration checks or listener startup splits recursively until compatible subsets start and individual incompatible inputs receive `start_failed`; ordinary request failures do not restart batches. All temporary files are private and removed, and child processes and workers are stopped after each batch or interruption.
- Progress includes completed/total and passed counts, plus elapsed time. A final validation elapsed time is printed even when interrupted. With 632 parseable inputs and no startup failures, validation uses 13 temporary running processes over the whole run instead of 632.
- Each attempt makes **both** a SOCKS5 and an HTTP request to `http://cp.cloudflare.com/generate_204`. An attempt succeeds only if both return exactly 204. A tunnel passes if at least N of M attempts succeed; defaults are 2 of 3. Redirects do not count. Each request has its own total timeout covering connection, authentication, headers, and body. With M attempts, a dead tunnel can take roughly `2 × M × timeout`, plus startup/check time.
- The reported latency is the median of the successful SOCKS5 and HTTP request durations from successful paired attempts, including proxy authentication and tunnel connection time. Country is fetched separately through that same proxy from `https://ipinfo.io/json`. A country lookup failure or rate limit records `UNKNOWN` and does not disqualify a working tunnel.
- Every final mixed inbound routes to exactly its own WireGuard endpoint. Its DNS queries also use that endpoint, via `--dns-server` (default `1.1.1.1`). DNS resolution is IPv4-only and caching is disabled to keep DNS observations within each tunnel. There is no direct outbound or automatic failover; unmatched and IPv6 traffic is rejected. Endpoint bootstrap DNS and public-IP detection use the host network before deployment.
- All endpoints use MTU **1280**, userspace networking (`system: false`), one worker, and full IPv4 peer routing (`0.0.0.0/0`). Source `MTU`, `AllowedIPs`, `DNS`, `ListenPort`, and shell hooks such as `PostUp` are not imported. Hooks are never executed. This intentionally turns single-peer client exports into full IPv4 proxies. Configurations using provider-specific reserved bytes or multiple peers require adaptation and are not supported.

Use `--test-url`, `--expected-status`, and `--dns-server` to adapt validation to your provider. Successful validation measures reachability at build time; it cannot guarantee future availability. Avoid concurrent clients or duplicate inputs using the same WireGuard identity on the same peer: WireGuard endpoint roaming can disrupt them.

## Output files

All generated files, including the lock file and temporary configs, have mode **600**. New output directories have mode **700**. Treat configs and exports as secrets. Each successful build writes:

| File | Contents |
| --- | --- |
| `output/sing-box.json` | Final authenticated sing-box config; includes private keys |
| `output/socks5.txt` | `socks5://user:pass@ip:port`, one per line |
| `output/http.txt` | `http://user:pass@ip:port`, one per line |
| `output/plain.txt` | `ip:port:user:pass`, one per line |
| `output/report.csv` | `file_name,port,country,latency_ms,status`; no passwords or keys |

Credentials in URLs are percent-encoded; the plain format uses the original credentials. For clients that distinguish SOCKS DNS modes, select remote/proxy DNS (for example curl's `--socks5-hostname` or a client's `socks5h` mode).

Report statuses are `selected`, `not_selected` (passed but outside the limit), `failed`, `invalid`, and `start_failed`. Excluded inputs have no port; unmeasured latencies are blank. A rebuild first invalidates the previous config and proxy lists in that output directory. If no inputs pass, only the CSV report is produced. A failed build never changes an already running service. Use a separate output directory to retain an earlier export. Concurrent builds sharing an output directory are rejected.

## Service and health checks

Deployment checks the candidate with `sing-box check`, installs the config at `/etc/sing-box/wgproxy.json` with mode 600, and creates `/etc/systemd/system/sing-box-wgproxy.service`. The unit contains no credentials and uses normal systemd metadata permissions (644). It has `TasksMax=infinity`, `LimitNOFILE=65535`, `Restart=on-failure`, and `UMask=0077`. It uses userspace tunnels, requires no kernel WireGuard interface, and does not modify host routes.

Before starting, deployment binds every requested TCP address/port to detect conflicts. When replacing this project's own active service, it stops it for that check and restores the prior config and service if startup fails. An unrelated sing-box service is not stopped. There is a small unavoidable interval between the port check and sing-box binding; startup/listener checks catch those failures. `run.py` also rolls back if its automatic reachability check fails. The advanced `python3 -m wgproxy deploy` command checks listener startup only; use the health command afterward or use `python3 -m wgproxy run` for the complete workflow.

```bash
sudo systemctl status sing-box-wgproxy.service
sudo systemctl restart sing-box-wgproxy.service
sudo systemctl disable --now sing-box-wgproxy.service

# Default: one request per protocol, local listeners, deployed config.
sudo python3 -m wgproxy health-check

# Check a generated config, or probe the server from another machine.
python3 -m wgproxy health-check --config ./output/sing-box.json
python3 -m wgproxy health-check --config ./output/sing-box.json --host YOUR_SERVER_IPV4 \
  --test-attempts 3 --min-successes 2 --test-timeout 8 --test-concurrency 2
```

Health checks read credentials directly from the selected config, test SOCKS5 and HTTP independently, and print per-port results plus OK/FAIL counts for each protocol and for complete proxies. Exit status is 0 only when every proxy passes both protocols; failures return 1 and interruption returns 130. Local checks use `127.0.0.1` for a wildcard listen address. Remote checks also exercise your firewall and NAT.

Low-memory defaults use `GOMEMLIMIT=192MiB` for the single validation process and `384MiB` for the deployed process, with `GOGC=50`. These are Go garbage-collection targets, not hard memory limits. Each extra endpoint consumes memory; reduce batch size on constrained hosts and keep a modest `MAX_PROXIES`. Swap is created before validation when requested. It skips creation if any swap is active. Otherwise it allocates a 2 GiB `/swapfile-wgproxy`, sets mode 600, enables it, and adds it to `/etc/fstab`. It requires at least 3 GiB free disk and a filesystem supporting swap files (Ubuntu's usual ext4 works).

Python diagnostics never include raw parser errors, subprocess output, passwords, or private keys. sing-box application logs are disabled, including temporary validation processes; the service discards stdout/stderr. systemd still records service lifecycle failures. The CSV provides validation outcomes without secrets.

## Development

```bash
python3 -m unittest discover -v
```

Tests use only the standard library. With sing-box installed, integration tests generate ephemeral keys and run real local WireGuard peers to check authenticated mixed traffic, per-port routing, dead-tunnel behavior, validation, and health checks. They do not need VPN credentials or public Internet access. Without sing-box, integration tests are skipped.

The modules separate parsing/configuration (`core.py`), protocol clients (`network.py`), batched validation/health (`validation.py`), literal settings and persistent credentials (`settings.py`), installation/systemd (`deploy.py`), and command handling (`cli.py`). `run.py` selects the full workflow by default.

Official sing-box references: [WireGuard endpoints](https://sing-box.sagernet.org/configuration/endpoint/wireguard/), [mixed inbounds](https://sing-box.sagernet.org/configuration/inbound/mixed/), [DNS servers](https://sing-box.sagernet.org/configuration/dns/server/udp/), and [route actions](https://sing-box.sagernet.org/configuration/route/rule_action/).
