"""Local integration tests use ephemeral keys and real userspace WireGuard tunnels."""

from contextlib import contextmanager
import http.server
import io
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from wgproxy.cli import main
from wgproxy.core import WireGuard, make_config, private_write
from wgproxy.network import Proxy, RequestError, request
from wgproxy.validation import TestOptions, check_config, find_sing_box, free_port, health_check, temporary_instance, validate_one

BINARY = shutil.which("sing-box")


def keypair():
    output = subprocess.run([BINARY, "generate", "wg-keypair"], capture_output=True, check=True).stdout.decode()
    values = re.findall(r"[A-Za-z0-9+/]{43}=", output)
    if len(values) != 2:
        raise RuntimeError("Cannot parse generated test keys.")
    return values


@contextmanager
def origin(status):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def dns_server(answer):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.1)
    stop, queries = threading.Event(), []

    def serve():
        while not stop.is_set():
            try:
                packet, source = sock.recvfrom(4096)
            except socket.timeout:
                continue
            offset = 12
            while packet[offset]:
                offset += packet[offset] + 1
            question = packet[12:offset + 5]
            queries.append(question)
            response = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + question +
                        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer))
            sock.sendto(response, source)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1], queries
    finally:
        stop.set()
        thread.join(timeout=1)
        sock.close()


@contextmanager
def peer_server(origin_port, dns_port=None):
    private, public = keypair()
    client_private, client_public = keypair()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]
    config = {
        "log": {"disabled": True},
        "endpoints": [{"type": "wireguard", "tag": "server", "system": False,
                       "mtu": 1280, "address": ["10.77.0.1/24"], "private_key": private,
                       "listen_port": port, "workers": 1,
                       "peers": [{"public_key": client_public, "allowed_ips": ["10.77.0.2/32"]}]}],
        "outbounds": [{"type": "direct", "tag": "local"}],
        "route": {"rules": [{"inbound": ["server"], "action": "route", "outbound": "local",
                             "override_address": "127.0.0.1", "override_port": origin_port}]},
    }
    if dns_port is not None:
        config["route"]["rules"].insert(0, {
            "inbound": ["server"], "network": "udp", "port": 53,
            "action": "route", "outbound": "local", "override_address": "127.0.0.1",
            "override_port": dns_port,
        })
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "server.json"
        private_write(path, json.dumps(config))
        check_config(BINARY, path)
        process = subprocess.Popen([BINARY, "run", "-c", str(path)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.15)
            if process.poll() is not None:
                raise RuntimeError("Local test WireGuard server failed to start.")
            yield WireGuard("valid.conf", client_private, ("10.77.0.2/32",), public, "", "127.0.0.1", port)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@unittest.skipUnless(BINARY, "sing-box is required for local integration tests")
class IntegrationTests(unittest.TestCase):
    def test_dns_queries_travel_through_each_own_tunnel(self):
        with origin(204) as first_origin, origin(205) as second_origin:
            with dns_server("192.0.2.10") as (first_dns, first_queries), dns_server("192.0.2.20") as (second_dns, second_queries):
                with peer_server(first_origin, first_dns) as first, peer_server(second_origin, second_dns) as second:
                    ports = [free_port(), free_port()]
                    while ports[0] == ports[1]:
                        ports[1] = free_port()
                    config = make_config(list(zip((first, second), ports)), "127.0.0.1", "u", "p", "203.0.113.53")
                    with temporary_instance(BINARY, config, 3, threading.Event()):
                        for index, port in enumerate(ports):
                            for protocol in ("socks5", "http"):
                                self.assertEqual(request(Proxy("127.0.0.1", port, "u", "p"), protocol,
                                                         "http://origin.test/", 3)[0], 204 + index)
                    self.assertEqual(len(first_queries), 2)
                    self.assertEqual(len(second_queries), 2)

    def test_two_real_tunnels_mixed_protocols_isolation_and_auth(self):
        with origin(204) as first_origin, origin(205) as second_origin:
            with peer_server(first_origin) as first, peer_server(second_origin) as second:
                first_port, second_port = free_port(), free_port()
                while second_port == first_port:
                    second_port = free_port()
                config = make_config([(first, first_port), (second, second_port)], "127.0.0.1", "user", "private-test-password")
                cancel = threading.Event()
                with temporary_instance(BINARY, config, 3, cancel):
                    for port, expected in ((first_port, 204), (second_port, 205)):
                        for protocol in ("socks5", "http"):
                            status, _, _ = request(Proxy("127.0.0.1", port, "user", "private-test-password"), protocol,
                                                   "http://192.0.2.100/test", 3)
                            self.assertEqual(status, expected)
                            wrong = Proxy("127.0.0.1", port, "user", "wrong-password")
                            if protocol == "socks5":
                                with self.assertRaises(RequestError):
                                    request(wrong, protocol, "http://192.0.2.100/test", 1)
                            else:
                                self.assertEqual(request(wrong, protocol, "http://192.0.2.100/test", 1)[0], 407)
                    for protocol in ("socks5", "http"):
                        with self.assertRaises(RequestError):
                            request(Proxy("127.0.0.1", first_port, "user", "private-test-password"), protocol,
                                    "http://[::1]/", 1)

    def test_dead_tunnel_never_uses_direct_network(self):
        with origin(204) as origin_port:
            private, _ = keypair()
            _, public = keypair()
            wg = WireGuard("dead.conf", private, ("10.77.0.2/32",), public, "", "127.0.0.1", free_port())
            port = free_port()
            config = make_config([(wg, port)], "127.0.0.1", "u", "p")
            with temporary_instance(BINARY, config, 3, threading.Event()):
                for protocol in ("socks5", "http"):
                    with self.assertRaises(RequestError):
                        request(Proxy("127.0.0.1", port, "u", "p"), protocol,
                                f"http://127.0.0.1:{origin_port}/", 0.25)

    def test_validation_build_and_health_workflow(self):
        from contextlib import redirect_stderr, redirect_stdout
        with origin(204) as origin_port, peer_server(origin_port) as wg:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                configs = root / "configs"
                configs.mkdir()
                text = (f"[Interface]\nPrivateKey = {wg.private_key}\nAddress = {wg.addresses[0]}\n"
                        f"[Peer]\nPublicKey = {wg.public_key}\nEndpoint = {wg.endpoint}:{wg.endpoint_port}\n")
                private_write(configs / "valid.conf", text)
                private_write(configs / "invalid.conf", "PrivateKey = NEVER_LOG_THIS")
                output = io.StringIO()
                with patch("wgproxy.validation.exit_country", return_value="US"), redirect_stdout(output), redirect_stderr(output):
                    code = main(["build", "--config-dir", str(configs), "--output-dir", str(root / "output"),
                                 "--public-ip", "192.0.2.1", "--listen", "127.0.0.1", "--start-port", str(free_port()),
                                 "--test-url", "http://192.0.2.100/", "--test-attempts", "2", "--min-successes", "2",
                                 "--password", "NEVER_LOG_THIS_PASSWORD", "--test-timeout", "2"])
                self.assertEqual(code, 0, output.getvalue())
                self.assertNotIn(wg.private_key, output.getvalue())
                self.assertNotIn("NEVER_LOG_THIS", output.getvalue())
                config = json.loads((root / "output/sing-box.json").read_text())
                self.assertEqual(len(config["inbounds"]), 1)
                report = (root / "output/report.csv").read_text()
                self.assertIn("invalid", report)
                self.assertIn("selected", report)
                self.assertIn("US", report)
                with temporary_instance(BINARY, config, 3, threading.Event()):
                    rows, counts = health_check(config, TestOptions(1, 1, 2, 1, "http://192.0.2.100/", 204))
                    self.assertEqual(counts["ok"], 1)
                    self.assertEqual(rows[0][1:], (True, True))

    def test_request_deadline_covers_slow_headers(self):
        class SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(0.3)
                try:
                    self.send_response(204)
                    self.end_headers()
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        # A local HTTP endpoint is sufficient to exercise absolute-form and deadline handling.
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            with self.assertRaises(RequestError):
                request(Proxy("127.0.0.1", server.server_port, "u", "p"), "http", "http://example.test/", 0.08)
            self.assertLess(time.monotonic() - started, 0.25)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
