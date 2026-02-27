from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading
import urllib.request
import urllib.error
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = 8000

# Hop-by-hop headers that must not be forwarded
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}


class ProxyHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[PROXY] {self.address_string()} {format % args}")

    # ------------------------------------------------------------------
    # CONNECT — used by git for HTTPS tunneling
    # ------------------------------------------------------------------
    def do_CONNECT(self):
        try:
            host, _, port = self.path.rpartition(":")
            port = int(port) if port else 443
        except ValueError:
            self.send_error(400, "Bad CONNECT request")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {host}:{port}: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        self._tunnel(self.connection, remote)

    def _tunnel(self, client, remote):
        """Bidirectional raw socket tunnel (used for HTTPS/SSH-over-HTTPS)."""

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=forward, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    # ------------------------------------------------------------------
    # Plain HTTP forwarding (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
    # ------------------------------------------------------------------
    def do_GET(self):     self._forward("GET")      # noqa: E704
    def do_POST(self):    self._forward("POST")     # noqa: E704
    def do_PUT(self):     self._forward("PUT")      # noqa: E704
    def do_DELETE(self):  self._forward("DELETE")   # noqa: E704
    def do_HEAD(self):    self._forward("HEAD")     # noqa: E704
    def do_OPTIONS(self): self._forward("OPTIONS")  # noqa: E704
    def do_PATCH(self):   self._forward("PATCH")    # noqa: E704

    def _forward(self, method):
        target_url = self.path

        # Reject non-http(s) targets
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https", ""):
            self.send_error(400, "Only http/https allowed")
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Strip hop-by-hop headers before forwarding
        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in HOP_BY_HOP
        }

        try:
            req = urllib.request.Request(
                target_url,
                data=body,
                headers=fwd_headers,
                method=method,
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
                resp_headers = resp.headers
                resp_body = resp.read()

            self.send_response(status)
            for k, v in resp_headers.items():
                if k.lower() not in HOP_BY_HOP | {"transfer-encoding"}:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            err_body = e.read()
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in HOP_BY_HOP | {"transfer-encoding"}:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(err_body)

        except Exception as e:
            self.send_error(502, str(e))


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), ProxyHandler)
    print(f"Proxy running on http://{HOST}:{PORT}")
    print()
    print("Configure git (global):")
    print(f"  git config --global http.proxy  http://localhost:{PORT}")
    print(f"  git config --global https.proxy http://localhost:{PORT}")
    print()
    print("Or per-repo:")
    print(f"  git config http.proxy  http://localhost:{PORT}")
    print(f"  git config https.proxy http://localhost:{PORT}")
    print()
    print("Or via environment (one-off):")
    print(f"  HTTPS_PROXY=http://localhost:{PORT} git push")
    server.serve_forever()
