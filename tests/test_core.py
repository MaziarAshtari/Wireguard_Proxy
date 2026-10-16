from contextlib import nullcontext, redirect_stderr, redirect_stdout
import base64
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from wgproxy.cli import main
from wgproxy.core import AppError, Result, WireGuard, credentials, make_config, parse_wireguard, private_write, write_outputs
from wgproxy.deploy import load_config, unit_text
from wgproxy.validation import TestOptions, check_ports, select_best, validate_files, validate_one

KEY = base64.b64encode(bytes(range(32))).decode()
OTHER_KEY = base64.b64encode(bytes(reversed(range(32)))).decode()


def tunnel(filename="test.conf"):
    return WireGuard(filename, KEY, ("10.0.0.2/32",), OTHER_KEY, "", "127.0.0.1", 51820)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def config_file(self, extra="", peer_extra=""):
        path = self.directory / "test.conf"
        path.write_text(f"""[Interface]
PrivateKey = {KEY}
Address = 10.0.0.2/32, fd00::2/128
{extra}
[Peer]
PublicKey = {OTHER_KEY}
PresharedKey = {KEY}
Endpoint = 127.0.0.1:51820
{peer_extra}
""")
        return path

    def test_parse_ipv4_and_no_hook_execution(self):
        wg = parse_wireguard(self.config_file("PostUp = touch /never-execute\nMTU = 1500"))
        self.assertEqual(wg.addresses, ("10.0.0.2/32",))
        self.assertEqual(wg.preshared_key, KEY)
        self.assertEqual(wg.endpoint_port, 51820)
        self.assertNotIn(KEY, repr(wg))

    def test_invalid_keys_and_multiple_peers_are_sanitized(self):
        path = self.config_file()
        path.write_text(path.read_text().replace(f"PrivateKey = {KEY}", "PrivateKey = SUPER_SECRET"))
        with self.assertRaises(AppError) as error:
            parse_wireguard(path)
        self.assertNotIn("SUPER_SECRET", str(error.exception))
        path = self.config_file(peer_extra=f"[Peer]\nPublicKey = {KEY}")
        with self.assertRaises(AppError):
            parse_wireguard(path)

    def test_ipv6_only_and_ipv6_endpoint_rejected(self):
        path = self.config_file()
        path.write_text(path.read_text().replace("10.0.0.2/32, ", ""))
        with self.assertRaises(AppError):
            parse_wireguard(path)
        path = self.config_file()
        path.write_text(path.read_text().replace("127.0.0.1:51820", "[::1]:51820"))
        with self.assertRaises(AppError):
            parse_wireguard(path)

    def test_hostname_resolves_only_ipv4(self):
        path = self.config_file()
        path.write_text(path.read_text().replace("127.0.0.1:51820", "vpn.example:51820"))
        with patch("wgproxy.core.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.7", 51820))]) as resolve:
            self.assertEqual(parse_wireguard(path).endpoint, "192.0.2.7")
            self.assertEqual(resolve.call_args.args[2], socket.AF_INET)

    def test_routes_and_dns_are_isolated(self):
        config = make_config([(tunnel(), 12000), (tunnel("second.conf"), 12001)], "0.0.0.0", "user", "password")
        self.assertNotIn("outbounds", config)
        self.assertEqual(config["route"]["rules"][-1], {"action": "reject"})
        self.assertEqual(config["route"]["rules"][0], {"ip_version": 6, "action": "reject"})
        for index in range(2):
            self.assertEqual(config["inbounds"][index]["type"], "mixed")
            self.assertTrue(config["inbounds"][index]["users"])
            self.assertEqual(config["endpoints"][index]["mtu"], 1280)
            self.assertEqual(config["endpoints"][index]["workers"], 1)
            self.assertEqual(config["dns"]["servers"][index]["detour"], f"wg-{index}")
            self.assertEqual(config["route"]["rules"][index * 2 + 2]["outbound"], f"wg-{index}")
        self.assertTrue(config["log"]["disabled"])

    def test_ranking_exclusion_and_port_overflow(self):
        results = [Result("slow", status="passed", latency_ms=20), Result("bad"),
                   Result("fast", status="passed", latency_ms=5)]
        selected = select_best(results, 12000, 1)
        self.assertEqual([r.filename for r in selected], ["fast"])
        self.assertEqual(selected[0].port, 12000)
        self.assertEqual(results[0].status, "not_selected")
        self.assertIsNone(results[1].port)
        self.assertEqual(select_best([Result("edge", status="passed", latency_ms=1)], 65535, 0)[0].port, 65535)
        with self.assertRaises(AppError):
            select_best([Result("a", status="passed", latency_ms=1), Result("b", status="passed", latency_ms=2)], 65535, 0)

    def test_files_private_and_passwords_encoded_only_in_exports(self):
        secret = "p@ss/word?#%"
        config = make_config([(tunnel(), 12000)], "0.0.0.0", "a@b", secret)
        write_outputs(self.directory, config, "192.0.2.1", [Result("test.conf", status="selected", port=12000)])
        for name in ("sing-box.json", "socks5.txt", "http.txt", "plain.txt", "report.csv"):
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)
        self.assertIn("socks5://a%40b:p%40ss%2Fword%3F%23%25@192.0.2.1:12000", (self.directory / "socks5.txt").read_text())
        self.assertEqual((self.directory / "plain.txt").read_text(), f"192.0.2.1:12000:a@b:{secret}\n")
        report = (self.directory / "report.csv").read_text()
        self.assertNotIn(secret, report)
        self.assertNotIn(KEY, report)
        self.assertEqual(load_config(self.directory / "sing-box.json"), config)

    def test_atomic_write_replaces_symlink(self):
        target = self.directory / "target"
        target.write_text("unchanged")
        destination = self.directory / "link"
        destination.symlink_to(target)
        private_write(destination, "new")
        self.assertEqual(target.read_text(), "unchanged")
        self.assertFalse(destination.is_symlink())

    def test_credentials_reject_ambiguous_raw_format(self):
        for username, password in (("user:name", "pass"), ("user", "bad\npass"), ("", "pass"), ("user", "x" * 256)):
            with self.assertRaises(AppError):
                credentials(username, password)

    def test_port_check_detects_occupied_and_duplicate_ports(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            config = make_config([(tunnel(), port)], "0.0.0.0", "u", "p")
            with self.assertRaises(AppError):
                check_ports(config)
        config = make_config([(tunnel(), port), (tunnel(), port)], "127.0.0.1", "u", "p")
        with self.assertRaises(AppError):
            check_ports(config)

    def test_service_limits_and_safe_diagnostics(self):
        text = unit_text("/usr/local/bin/sing-box")
        for line in ("TasksMax=infinity", "LimitNOFILE=65535", "Restart=on-failure", "UMask=0077"):
            self.assertIn(line, text)
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit):
            main(["build", "--config-dir", "missing", "--invalid", "MY_PASSWORD"])
        self.assertNotIn("MY_PASSWORD", output.getvalue())

    def test_batch_concurrency_is_bounded(self):
        import threading
        import time
        active = maximum = 0
        lock = threading.Lock()

        def validate(result, *args):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            return result

        with patch("wgproxy.validation.parse_wireguard", side_effect=lambda path: tunnel(path.name)), \
                patch("wgproxy.validation.temporary_instance", side_effect=lambda *args: nullcontext()), \
                patch("wgproxy.validation._check_tunnel", side_effect=validate):
            results = validate_files([Path(str(i)) for i in range(17)], "unused",
                                     TestOptions(concurrency=2, batch_size=5), "1.1.1.1")
        self.assertEqual(len(results), 17)
        self.assertEqual(maximum, 2)

    def test_validation_threshold_requires_both_protocols_in_each_attempt(self):
        import threading
        for replies, expected in (([204, 500, 500, 204, 204, 204], "failed"),
                                  ([204, 204, 500, 204, 204, 204], "passed")):
            with patch("wgproxy.validation.parse_wireguard", return_value=tunnel()), \
                    patch("wgproxy.validation.temporary_instance", return_value=nullcontext(12000)), \
                    patch("wgproxy.validation.request", side_effect=[(status, b"", float(i)) for i, status in enumerate(replies)]), \
                    patch("wgproxy.validation.exit_country", return_value="US"):
                result = validate_one(Path("input.conf"), "unused", TestOptions(3, 2), "1.1.1.1", threading.Event())
            self.assertEqual(result.status, expected)
            if expected == "passed":
                self.assertEqual(result.latency_ms, 2.5)
                self.assertEqual(result.country, "US")


if __name__ == "__main__":
    unittest.main()
