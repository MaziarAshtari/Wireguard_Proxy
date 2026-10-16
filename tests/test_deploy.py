"""Privileged workflows are tested with temporary files and mocked system commands."""

from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from wgproxy.core import AppError, make_config, private_write
from wgproxy.deploy import SERVICE, create_swap, deploy_config, install_sing_box, load_config
from tests.test_core import tunnel


class DeployTests(unittest.TestCase):
    def test_download_digest_is_verified_before_installation(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            member = tarfile.TarInfo("sing-box-1.14.3-linux-amd64/sing-box")
            payload = b"test executable"
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        body = archive.getvalue()
        asset = {"name": "sing-box-1.14.3-linux-amd64.tar.gz",
                 "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                 "browser_download_url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz"}
        release = {"tag_name": "v1.14.3", "assets": [asset]}
        with patch("wgproxy.deploy.require_root"), patch("wgproxy.deploy.shutil.which", return_value=None), \
                patch("wgproxy.deploy._download", side_effect=[json.dumps(release).encode(), body]), \
                patch("wgproxy.deploy.find_sing_box", return_value="/usr/local/bin/sing-box"), \
                patch("wgproxy.deploy.private_write") as write:
            self.assertEqual(install_sing_box(), "/usr/local/bin/sing-box")
            self.assertEqual(write.call_args.args, (Path("/usr/local/bin/sing-box"), payload, 0o755))
        asset["digest"] = "sha256:" + "0" * 64
        with patch("wgproxy.deploy.require_root"), patch("wgproxy.deploy.shutil.which", return_value=None), \
                patch("wgproxy.deploy._download", side_effect=[json.dumps(release).encode(), body]), \
                patch("wgproxy.deploy.private_write") as write:
            with self.assertRaises(AppError):
                install_sing_box()
            write.assert_not_called()

    def test_swap_skips_any_active_swap(self):
        with patch("wgproxy.deploy.require_root"), patch("wgproxy.deploy.Path.read_text", return_value="Filename Type Size Used Priority\n/dev/zram0 partition 1024 0 5\n"), \
                patch("wgproxy.deploy._run") as run:
            self.assertFalse(create_swap())
            run.assert_not_called()

    def test_swap_allocates_two_gib_and_persists(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "swapfile"
            with patch("wgproxy.deploy.require_root"), \
                    patch("wgproxy.deploy.Path.read_text", side_effect=["Filename Type Size Used Priority\n", "# fstab\n"]), \
                    patch("wgproxy.deploy.shutil.disk_usage", return_value=SimpleNamespace(free=4 * 1024 ** 3)), \
                    patch("wgproxy.deploy.os.posix_fallocate") as allocate, \
                    patch("wgproxy.deploy._run") as run, patch("wgproxy.deploy.private_write") as write:
                self.assertTrue(create_swap(path))
                self.assertEqual(allocate.call_args.args[1:], (0, 2 * 1024 ** 3))
                self.assertEqual([call.args[0][0] for call in run.call_args_list], ["mkswap", "swapon"])
                self.assertIn(f"{path} none swap sw 0 0", write.call_args.args[1])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_modified_routing_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            config = make_config([(tunnel(), 12000)], "127.0.0.1", "u", "p")
            config["route"]["rules"][-1] = {"action": "route", "outbound": "direct"}
            private_write(path, json.dumps(config))
            with self.assertRaises(AppError):
                load_config(path)

    def test_deploy_checks_ports_and_rolls_back_failed_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, installed, unit = directory / "source.json", directory / "installed.json", directory / "service.unit"
            config = make_config([(tunnel(), 12000)], "127.0.0.1", "u", "p")
            private_write(source, json.dumps(config))
            private_write(installed, b"old config")
            private_write(unit, b"old unit")
            actions = []

            def run(command, **kwargs):
                actions.append(command)
                if command[1] == "restart":
                    raise AppError("Simulated start failure.")

            with ExitStack() as stack:
                stack.enter_context(patch("wgproxy.deploy.require_root"))
                stack.enter_context(patch("wgproxy.deploy.CONFIG_PATH", installed))
                stack.enter_context(patch("wgproxy.deploy.UNIT_PATH", unit))
                check = stack.enter_context(patch("wgproxy.deploy.check_config"))
                ports = stack.enter_context(patch("wgproxy.deploy.check_ports", side_effect=lambda c: actions.append(["ports"])))
                stack.enter_context(patch("wgproxy.deploy.subprocess.run", return_value=SimpleNamespace(returncode=0)))
                stack.enter_context(patch("wgproxy.deploy._run", side_effect=run))
                with self.assertRaises(AppError):
                    deploy_config("/usr/local/bin/sing-box", source)
                check.assert_called_once()
                ports.assert_called_once()
            self.assertLess(actions.index(["ports"]), actions.index(["systemctl", "restart", SERVICE]))
            self.assertEqual(installed.read_bytes(), b"old config")
            self.assertEqual(unit.read_bytes(), b"old unit")
            self.assertEqual(actions[-1], ["systemctl", "start", SERVICE])

    def test_port_conflict_restores_previously_running_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, installed, unit = directory / "source.json", directory / "installed.json", directory / "service.unit"
            config = make_config([(tunnel(), 12000)], "127.0.0.1", "u", "p")
            private_write(source, json.dumps(config))
            with patch("wgproxy.deploy.require_root"), patch("wgproxy.deploy.CONFIG_PATH", installed), \
                    patch("wgproxy.deploy.UNIT_PATH", unit), patch("wgproxy.deploy.check_config"), \
                    patch("wgproxy.deploy.check_ports", side_effect=AppError("Port conflict.")), \
                    patch("wgproxy.deploy.subprocess.run", return_value=SimpleNamespace(returncode=0)), \
                    patch("wgproxy.deploy._run") as run:
                with self.assertRaises(AppError):
                    deploy_config("/usr/local/bin/sing-box", source)
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [["systemctl", "stop", SERVICE], ["systemctl", "start", SERVICE]])
            self.assertFalse(installed.exists())

    def test_health_failure_rolls_back_previous_deployment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, installed, unit = directory / "source.json", directory / "installed.json", directory / "service.unit"
            config = make_config([(tunnel(), 12000)], "127.0.0.1", "u", "p")
            private_write(source, json.dumps(config))
            private_write(installed, b"old config")
            private_write(unit, b"old unit", 0o644)

            def verify(candidate):
                self.assertEqual(candidate, config)
                raise AppError("Health check failed.")

            with patch("wgproxy.deploy.require_root"), patch("wgproxy.deploy.CONFIG_PATH", installed), \
                    patch("wgproxy.deploy.UNIT_PATH", unit), patch("wgproxy.deploy.check_config"), \
                    patch("wgproxy.deploy.check_ports"), patch("wgproxy.deploy.socket.create_connection"), \
                    patch("wgproxy.deploy.subprocess.run", return_value=SimpleNamespace(returncode=0)), \
                    patch("wgproxy.deploy._run") as run:
                with self.assertRaises(AppError):
                    deploy_config("/usr/local/bin/sing-box", source, verify=verify)
            self.assertEqual(installed.read_bytes(), b"old config")
            self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertEqual(unit.read_bytes(), b"old unit")
            self.assertEqual(run.call_args.args[0], ["systemctl", "start", SERVICE])


if __name__ == "__main__":
    unittest.main()
