"""Protocol framing tests use only loopback sockets and the standard library."""

from contextlib import contextmanager
import http.client
import socketserver
import threading
import unittest
from unittest.mock import Mock, patch

from wgproxy.network import Proxy, RequestError, exit_country, public_ipv4, request


@contextmanager
def proxy_server():
    received = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                headers = bytearray()
                while not headers.endswith(b"\r\n\r\n"):
                    value = self.rfile.read(1)
                    if not value:
                        return
                    headers.extend(value)
                received.append(bytes(headers))
                if headers.startswith(b"CONNECT "):
                    self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                else:
                    self.wfile.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class NetworkTests(unittest.TestCase):
    def test_http_absolute_form_and_authenticated_connect(self):
        with proxy_server() as (port, received):
            proxy = Proxy("127.0.0.1", port, "user", "secret")
            self.assertEqual(request(proxy, "http", "http://example.test/path?x=1", 1)[0], 204)
            self.assertTrue(received[0].startswith(b"GET http://example.test:80/path?x=1 HTTP/1.1"))
            self.assertIn(b"Proxy-Authorization: Basic ", received[0])
            # Keep this test local: check CONNECT framing and TLS setup independently
            # of certificates by replacing just the socket's TLS wrapping operation.
            context = Mock()
            context.wrap_socket.side_effect = lambda sock, **kwargs: sock
            with patch("wgproxy.network.ssl.create_default_context", return_value=context):
                self.assertEqual(request(proxy, "http", "https://example.test/secure", 1)[0], 204)
            self.assertTrue(received[1].startswith(b"CONNECT example.test:443 HTTP/1.1"))
            self.assertIn(b"Proxy-Authorization: Basic ", received[1])
            self.assertTrue(received[2].startswith(b"GET /secure HTTP/1.1"))
            self.assertNotIn(b"Proxy-Authorization", received[2])
            self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "example.test")

    def test_country_is_best_effort_and_validated(self):
        proxy = Proxy("127.0.0.1", 1, "u", "p")
        for response, expected in (((200, b'{"country":"us"}', 1), "US"),
                                   ((429, b"rate limited", 1), "UNKNOWN"),
                                   ((200, b'{"country":"SECRET_VALUE"}', 1), "UNKNOWN"),
                                   ((200, b"[]", 1), "UNKNOWN")):
            with patch("wgproxy.network.request", return_value=response):
                self.assertEqual(exit_country(proxy, 1), expected)
        with patch("wgproxy.network.request", side_effect=RequestError("failure")):
            self.assertEqual(exit_country(proxy, 1), "UNKNOWN")

    def test_public_ip_uses_numeric_ipv4_https_and_rejects_private_addresses(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b"fl=sample\nip=8.8.8.8\n"
        with patch("wgproxy.network.http.client.HTTPSConnection", return_value=connection) as factory:
            self.assertEqual(public_ipv4(1), "8.8.8.8")
            self.assertEqual(factory.call_args.args[0], "1.1.1.1")
        response.read.return_value = b"ip=10.0.0.2\n"
        from wgproxy.core import AppError
        with patch("wgproxy.network.http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(AppError):
                public_ipv4(1)


if __name__ == "__main__":
    unittest.main()
