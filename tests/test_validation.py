from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch

from wgproxy.core import AppError, make_config
from wgproxy.validation import (InstanceStartError, TestOptions, free_ports,
                                temporary_instance, validate_files)
from tests.test_core import tunnel


class BatchTests(unittest.TestCase):
    def test_632_inputs_use_13_processes_and_matching_proxies(self):
        configs, progress, seen = [], [], set()
        active = 0

        @contextmanager
        def instance(binary, config, *args):
            nonlocal active
            self.assertEqual(active, 0)
            configs.append(config)
            active += 1
            try:
                yield
            finally:
                active -= 1

        def request(proxy, protocol, url, timeout):
            self.assertEqual(active, 1)
            config = configs[-1]
            inbound = next(item for item in config["inbounds"] if item["listen_port"] == proxy.port)
            self.assertEqual(proxy.host, "127.0.0.1")
            self.assertEqual(proxy.password, inbound["users"][0]["password"])
            self.assertGreater(len(proxy.password), 32)
            return 204, b"", 2.5

        paths = [Path(f"{i}.conf") for i in range(632)]
        with patch("wgproxy.validation.parse_wireguard", side_effect=lambda path: tunnel(path.name)), \
                patch("wgproxy.validation.temporary_instance", side_effect=instance), \
                patch("wgproxy.validation.request", side_effect=request), \
                patch("wgproxy.validation.exit_country", return_value="US"):
            results = validate_files(paths, "unused", TestOptions(1, 1), "1.1.1.1", progress.append)
        self.assertEqual([len(config["inbounds"]) for config in configs], [50] * 12 + [32])
        self.assertEqual([r.filename for r in results], [p.name for p in paths])
        self.assertEqual(len(progress), 632)
        self.assertTrue(all(r.status == "passed" and r.country == "US" and r.latency_ms == 2.5 for r in results))
        for config in configs:
            self.assertTrue(config["log"]["disabled"])
            self.assertEqual(len({item["listen_port"] for item in config["inbounds"]}), len(config["inbounds"]))
            for index, item in enumerate(config["inbounds"]):
                self.assertEqual(item["listen"], "127.0.0.1")
                self.assertEqual(config["route"]["rules"][index * 2 + 2]["outbound"], f"wg-{index}")
                self.assertEqual(config["dns"]["servers"][index]["detour"], f"wg-{index}")
            password = config["inbounds"][0]["users"][0]["password"]
            self.assertNotIn(password, seen)
            seen.add(password)

    def test_bad_parse_and_bad_start_are_isolated_and_reported_once(self):
        sizes, progress = [], []

        def parse(path):
            if path.name == "invalid.conf":
                raise AppError("Invalid input.")
            return tunnel(path.name)

        @contextmanager
        def instance(binary, config, *args):
            sizes.append(len(config["endpoints"]))
            if any(endpoint["private_key"] == "incompatible" for endpoint in config["endpoints"]):
                raise InstanceStartError("Start failed.")
            yield

        from dataclasses import replace

        def parse_with_bad_start(path):
            wg = parse(path)
            return replace(wg, private_key="incompatible") if path.name == "bad.conf" else wg

        paths = [Path(name) for name in ("a.conf", "bad.conf", "invalid.conf", "b.conf", "c.conf")]
        with patch("wgproxy.validation.parse_wireguard", side_effect=parse_with_bad_start), \
                patch("wgproxy.validation.temporary_instance", side_effect=instance), \
                patch("wgproxy.validation.request", return_value=(204, b"", 1)), \
                patch("wgproxy.validation.exit_country", return_value="UNKNOWN"):
            results = validate_files(paths, "unused", TestOptions(1, 1), "1.1.1.1", progress.append)
        self.assertEqual([r.status for r in results], ["passed", "start_failed", "invalid", "passed", "passed"])
        self.assertEqual(sizes, [4, 2, 1, 1, 2])
        self.assertEqual(sorted(r.filename for r in progress), sorted(p.name for p in paths))

    def test_interrupt_drains_checks_before_process_cleanup(self):
        worker_started = threading.Event()
        worker_done = threading.Event()
        progress = []

        @contextmanager
        def instance(*args):
            try:
                yield
            finally:
                self.assertTrue(worker_done.is_set())

        def check(result, proxy, options, cancel):
            if result.filename == "interrupt.conf":
                self.assertTrue(worker_started.wait(2))
                raise KeyboardInterrupt
            worker_started.set()
            cancel.wait(2)
            worker_done.set()
            raise AppError("Interrupted.")

        with patch("wgproxy.validation.parse_wireguard", side_effect=lambda path: tunnel(path.name)), \
                patch("wgproxy.validation.temporary_instance", side_effect=instance), \
                patch("wgproxy.validation._check_tunnel", side_effect=check):
            with self.assertRaises(KeyboardInterrupt):
                validate_files([Path("wait.conf"), Path("interrupt.conf")], "unused",
                               TestOptions(concurrency=2), "1.1.1.1", progress.append)
        self.assertEqual(progress, [])

    def test_startup_checks_all_listeners_and_cleans_private_config(self):
        config = make_config([(tunnel(), port) for port in free_ports(2)], "127.0.0.1", "u", "private")
        process = Mock()
        process.poll.return_value = None
        addresses, paths = [], []

        def spawn(*args, **kwargs):
            path = Path(args[0][-1])
            paths.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), config)
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            return process

        def connect(address, **kwargs):
            addresses.append(address)
            from contextlib import nullcontext
            return nullcontext()

        with patch("wgproxy.validation.check_config"), patch("wgproxy.validation.subprocess.Popen", side_effect=spawn), \
                patch("wgproxy.validation.socket.create_connection", side_effect=connect):
            with temporary_instance("unused", config, 1, threading.Event()):
                self.assertEqual(set(addresses), {("127.0.0.1", i["listen_port"]) for i in config["inbounds"]})
                self.assertTrue(paths[0].exists())
        self.assertFalse(paths[0].exists())
        process.terminate.assert_called_once()
        process.wait.assert_called_once()

    def test_option_bounds_and_nonfinite_timeouts(self):
        for kwargs in ({"batch_size": 0}, {"batch_size": 201}, {"concurrency": 0},
                       {"concurrency": 129}, {"timeout": float("nan")}, {"timeout": float("inf")},
                       {"attempts": 1, "min_successes": 2}, {"url": "https://user:secret@host/"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(AppError):
                TestOptions(**kwargs).validate()
