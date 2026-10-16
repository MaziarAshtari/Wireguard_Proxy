from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wgproxy.cli import main
from wgproxy.core import AppError, Result, make_config, private_write
from wgproxy.settings import PROJECT_ROOT, load_settings, parse_dotenv, persistent_password
from tests.test_core import tunnel


class SettingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".env.example").write_bytes((PROJECT_ROOT / ".env.example").read_bytes())

    def env(self, text=""):
        private_write(self.root / ".env", text)

    def invoke(self, argv, simple=True):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = main(argv, simple=simple, project_root=self.root)
        return code, output.getvalue()

    def test_missing_env_is_copied_privately_and_no_pipeline_runs(self):
        with patch("wgproxy.cli.install_sing_box") as install:
            code, output = self.invoke([])
        self.assertEqual(code, 0)
        self.assertIn("Review", output)
        self.assertEqual((self.root / ".env").read_bytes(), (self.root / ".env.example").read_bytes())
        self.assertEqual((self.root / ".env").stat().st_mode & 0o777, 0o600)
        install.assert_not_called()
        self.assertFalse((self.root / ".wgproxy-password").exists())

    def test_parser_handles_comments_quotes_and_literal_shell_syntax(self):
        parsed = parse_dotenv('''# comment
USERNAME = 'proxy # one' # comment
PASSWORD="$(touch /never-run) ${TOKEN} # secret" # comment
PUBLIC_IP= # autodetect
CONFIG_DIR="path with spaces"
OUTPUT_DIR=output#literal
DNS_SERVER=1.1.1.1 # resolver
''')
        self.assertEqual(parsed["USERNAME"], "proxy # one")
        self.assertEqual(parsed["PASSWORD"], "$(touch /never-run) ${TOKEN} # secret")
        self.assertEqual(parsed["PUBLIC_IP"], "")
        self.assertEqual(parsed["OUTPUT_DIR"], "output#literal")
        self.assertEqual(parse_dotenv(r'PASSWORD="a\\b\"c"')["PASSWORD"], 'a\\b"c')
        for text in ('PASSWORD="SECRET', 'PASSWORD="SECRET" trailing', "PASSWORD=SECRET\nPASSWORD=OTHER",
                     "export PASSWORD=SECRET", "UNKNOWN=SECRET", "PASSWORD='SECRET\x00'"):
            with self.subTest(text=text), self.assertRaises(AppError) as error:
                parse_dotenv(text)
            self.assertNotIn("SECRET", str(error.exception))

    def test_example_loads_all_defaults_and_resolves_project_paths(self):
        self.env((self.root / ".env.example").read_text())
        settings = load_settings(self.root)
        self.assertEqual(settings.config_dir, self.root / "configs")
        self.assertEqual(settings.output_dir, self.root / "output")
        self.assertEqual((settings.batch_size, settings.test_concurrency, settings.max_proxies), (50, 32, 20))
        self.assertFalse(settings.create_swap)

    def test_invalid_settings_fail_before_install_and_never_echo_values(self):
        cases = (("START_PORT=0", "START_PORT"), ("START_PORT=SECRET", "START_PORT"),
                 ("MAX_PROXIES=-1", "MAX_PROXIES"), ("TEST_ATTEMPTS=0", "test-attempts"),
                 ("MIN_SUCCESSES=4", "min-successes"), ("TEST_TIMEOUT=nan", "TEST_TIMEOUT"),
                 ("TEST_TIMEOUT=inf", "TEST_TIMEOUT"), ("BATCH_SIZE=0", "BATCH_SIZE"),
                 ("TEST_CONCURRENCY=129", "TEST_CONCURRENCY"), ("CREATE_SWAP=SECRET", "CREATE_SWAP"),
                 ("CONFIG_DIR=", "CONFIG_DIR"), ("OUTPUT_DIR=", "OUTPUT_DIR"),
                 ("PUBLIC_IP=SECRET", "PUBLIC_IP"), ("DNS_SERVER=SECRET", "DNS_SERVER"),
                 ("LISTEN=SECRET", "LISTEN"), ("SING_BOX_VERSION=1.11.0", "SING_BOX_VERSION"),
                 ("TEST_URL=https://user:SECRET@example.com/", "TEST_URL"),
                 ("PASSWORD=SECRET:invalid", "PASSWORD"), ("USERNAME=", "USERNAME"))
        for content, expected in cases:
            self.env(content)
            with self.subTest(content=content), patch("wgproxy.cli.install_sing_box") as install:
                code, output = self.invoke([])
                self.assertEqual(code, 1)
                self.assertIn(expected, output)
                self.assertNotIn("SECRET", output)
                install.assert_not_called()

    def test_password_is_generated_once_even_for_concurrent_builds(self):
        path = self.root / ".wgproxy-password"
        with ThreadPoolExecutor(max_workers=8) as executor:
            passwords = list(executor.map(lambda _: persistent_password(path), range(16)))
        self.assertEqual(len(set(passwords)), 1)
        self.assertGreaterEqual(len(passwords[0]), 43)
        self.assertEqual(path.read_text().strip(), passwords[0])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.chmod(0o644)
        self.assertEqual(persistent_password(path), passwords[0])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_secret_files_reject_symlinks_and_invalid_stored_passwords(self):
        target = self.root / "target"
        target.write_text("unchanged")
        for name in (".env", ".wgproxy-password"):
            path = self.root / name
            path.symlink_to(target)
            with self.assertRaises(AppError):
                load_settings(self.root) if name == ".env" else persistent_password(path)
            path.unlink()
        self.assertEqual(target.read_text(), "unchanged")
        private_write(self.root / ".wgproxy-password", "bad:password")
        with self.assertRaises(AppError):
            persistent_password(self.root / ".wgproxy-password")

    def test_rebuild_reuses_credentials_and_flags_override_env(self):
        (self.root / "configs").mkdir()
        (self.root / "configs/one.conf").touch()
        self.env("PUBLIC_IP=192.0.2.1\nSTART_PORT=12000\nBATCH_SIZE=10\nTEST_CONCURRENCY=4\nCREATE_SWAP=true\n")

        def validate(paths, binary, options, dns, progress):
            result = Result("one.conf", tunnel(), "passed", "US", 1)
            progress(result)
            return [result]

        with patch("wgproxy.cli.find_sing_box", return_value="unused"), \
                patch("wgproxy.cli.validate_files", side_effect=validate) as checks, \
                patch("wgproxy.cli.check_config"), patch("wgproxy.cli.deploy_config") as deploy, \
                patch("wgproxy.cli.install_sing_box") as install, patch("wgproxy.cli.create_swap") as swap:
            self.assertEqual(self.invoke(["build"])[0], 0)
            first = json.loads((self.root / "output/sing-box.json").read_text())
            self.assertEqual(self.invoke(["build", "--start-port", "13000", "--batch-size", "25",
                                          "--test-concurrency", "8"], simple=False)[0], 0)
            second = json.loads((self.root / "output/sing-box.json").read_text())
            self.assertEqual(first["inbounds"][0]["users"], second["inbounds"][0]["users"])
            self.assertEqual(second["inbounds"][0]["listen_port"], 13000)
            self.assertEqual(checks.call_args.args[2].batch_size, 25)
            self.assertEqual(checks.call_args.args[2].concurrency, 8)
            deploy.assert_not_called()
            install.assert_not_called()
            swap.assert_not_called()
        for path in (self.root / "output").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_password_file_overrides_env_password(self):
        (self.root / "configs").mkdir()
        (self.root / "configs/one.conf").touch()
        self.env("PUBLIC_IP=192.0.2.1\nPASSWORD=FROM_ENV\n")
        private_write(self.root / "password.txt", "FROM_FILE\n")
        with patch("wgproxy.cli.find_sing_box", return_value="unused"), \
                patch("wgproxy.cli.validate_files", return_value=[Result("one.conf", tunnel(), "passed", "US", 1)]), \
                patch("wgproxy.cli.check_config"):
            code, output = self.invoke(["build", "--password-file", str(self.root / "password.txt")])
        self.assertEqual(code, 0, output)
        self.assertNotIn("FROM_FILE", output)
        self.assertNotIn("FROM_ENV", output)
        user = json.loads((self.root / "output/sing-box.json").read_text())["inbounds"][0]["users"][0]
        self.assertEqual(user["password"], "FROM_FILE")
        self.assertFalse((self.root / ".wgproxy-password").exists())

    def test_default_pipeline_orders_swap_before_build_and_runs_health(self):
        self.env("CREATE_SWAP=true\n")
        source = self.root / "output/sing-box.json"
        config = make_config([(tunnel(), 10000)], "127.0.0.1", "u", "SECRET")
        actions = []

        def deploy(binary, path, *, verify):
            actions.append("deploy")
            verify(config)

        with ExitStack() as stack:
            stack.enter_context(patch("wgproxy.cli.install_sing_box", side_effect=lambda *args: actions.append("install") or "unused"))
            stack.enter_context(patch("wgproxy.cli.create_swap", side_effect=lambda: actions.append("swap")))
            stack.enter_context(patch("wgproxy.cli.build", side_effect=lambda *args: actions.append("build") or source))
            stack.enter_context(patch("wgproxy.cli.load_config", return_value=config))
            stack.enter_context(patch("wgproxy.cli.deploy_config", side_effect=deploy))
            stack.enter_context(patch("wgproxy.cli.health_check", side_effect=lambda *args: actions.append("health") or
                                      ([(10000, True, True)], {"socks5_ok": 1, "http_ok": 1, "ok": 1})))
            code, output = self.invoke([])
        self.assertEqual(code, 0, output)
        self.assertEqual(actions, ["install", "swap", "build", "deploy", "health"])
        self.assertIn("selected 1; TCP ports 10000-10000; health OK", output)
        self.assertIn(str(source), output)
        self.assertNotIn("SECRET", output)

    def test_failed_pipeline_health_is_nonzero_and_no_create_swap_overrides_env(self):
        self.env("CREATE_SWAP=true\n")
        config = make_config([(tunnel(), 10000)], "127.0.0.1", "u", "SECRET")
        with patch("wgproxy.cli.install_sing_box", return_value="unused"), \
                patch("wgproxy.cli.create_swap") as swap, patch("wgproxy.cli.build", return_value=self.root / "output/sing-box.json"), \
                patch("wgproxy.cli.load_config", return_value=config), \
                patch("wgproxy.cli.deploy_config", side_effect=lambda binary, path, verify: verify(config)), \
                patch("wgproxy.cli.health_check", return_value=([(10000, True, False)], {"socks5_ok": 1, "http_ok": 0, "ok": 0})):
            code, output = self.invoke(["--no-create-swap"])
        self.assertEqual(code, 1)
        self.assertIn("health FAIL", output)
        swap.assert_not_called()

    def test_health_subcommand_does_not_build_or_install(self):
        self.env("TEST_ATTEMPTS=2\nMIN_SUCCESSES=2\n")
        config = make_config([(tunnel(), 10000)], "127.0.0.1", "u", "SECRET")
        with patch("wgproxy.cli.install_sing_box") as install, patch("wgproxy.cli.build") as build, \
                patch("wgproxy.cli.load_config", return_value=config), \
                patch("wgproxy.cli.health_check", return_value=([(10000, True, True)], {"socks5_ok": 1, "http_ok": 1, "ok": 1})) as health:
            code, output = self.invoke(["health-check"])
        self.assertEqual(code, 0, output)
        self.assertEqual(health.call_args.args[1].attempts, 2)
        install.assert_not_called()
        build.assert_not_called()
