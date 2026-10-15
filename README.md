# WireGuard mixed proxies

A small Python 3 project with no third-party Python dependencies. It validates a folder of WireGuard files, keeps the fastest working tunnels, and runs authenticated SOCKS5 and HTTP on one TCP port per tunnel using sing-box. Designed for Ubuntu 24.04 x86_64, including servers with about 1 GiB RAM.

## Setup

Use Ubuntu's Python 3.12 or newer. Run commands from this project directory; no pip installation is needed.

```bash
sudo apt-get update
sudo apt-get install -y python3 ca-certificates
python3 -m wgproxy --help

# Install sing-box if it is missing; optionally create 2 GiB swap.
sudo python3 -m wgproxy install --create-swap
mkdir -m 700 configs
# Copy your WireGuard .conf files into configs/.
chmod 600 configs/*.conf
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
  --test-concurrency 2 \
  --output-dir ./output

sudo python3 -m wgproxy deploy --config ./output/sing-box.json
sudo python3 -m wgproxy health-check
```

The password defaults to a fresh, cryptographically random 32-byte URL-safe token. It is stored in the config and proxy lists, never printed. To supply your own, use a mode-600 UTF-8 file with `--password-file ./proxy-password.txt`. A trailing newline is removed. `--password` is also supported, but its value can appear in shell history and process listings. Credentials must contain 1–255 UTF-8 bytes, with no colons or control characters, so all export formats stay unambiguous.

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
- Each temporary sing-box process has one userspace WireGuard endpoint and a randomly authenticated `mixed` inbound bound to `127.0.0.1` on an ephemeral port. Processes run in batches, with concurrency 2 by default and a maximum of 8. All temporary files are private and removed, and all child processes are stopped after each test or interruption.
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

Before starting, deployment binds every requested TCP address/port to detect conflicts. When replacing this project's own active service, it stops it for that check and restores the prior config and service if startup fails. An unrelated sing-box service is not stopped. There is a small unavoidable interval between the port check and sing-box binding; startup/listener checks catch those failures. Deployment starts the listeners; use the health command to check external reachability afterward.

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

Low-memory defaults use `GOMEMLIMIT=96MiB` per validation process and `384MiB` for the deployed process, with `GOGC=50`. These are Go garbage-collection targets, not hard memory limits. Start with concurrency 1 or 2 and a modest `--max-proxies`; each extra tunnel consumes memory. The optional swap command skips creation if any swap is active. Otherwise it allocates a 2 GiB `/swapfile-wgproxy`, sets mode 600, enables it, and adds it to `/etc/fstab`. It requires at least 3 GiB free disk and a filesystem supporting swap files (Ubuntu's usual ext4 works).

Python diagnostics never include raw parser errors, subprocess output, passwords, or private keys. sing-box application logs are disabled, including temporary validation processes; the service discards stdout/stderr. systemd still records service lifecycle failures. The CSV provides validation outcomes without secrets.

## Development

```bash
python3 -m unittest discover -v
```

Tests use only the standard library. With sing-box installed, integration tests generate ephemeral keys and run real local WireGuard peers to check authenticated mixed traffic, per-port routing, dead-tunnel behavior, validation, and health checks. They do not need VPN credentials or public Internet access. Without sing-box, integration tests are skipped.

The modules separate parsing/configuration (`core.py`), protocol clients (`network.py`), validation/health (`validation.py`), installation/systemd (`deploy.py`), and command handling (`cli.py`).

Official sing-box references: [WireGuard endpoints](https://sing-box.sagernet.org/configuration/endpoint/wireguard/), [mixed inbounds](https://sing-box.sagernet.org/configuration/inbound/mixed/), [DNS servers](https://sing-box.sagernet.org/configuration/dns/server/udp/), and [route actions](https://sing-box.sagernet.org/configuration/route/rule_action/).
