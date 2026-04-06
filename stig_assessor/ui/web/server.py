"""Native built-in web server for STIG Assessor UI."""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path

import tempfile

from stig_assessor.core.logging import Log
from stig_assessor.core.constants import MAX_POST_PAYLOAD
from stig_assessor.core.state import GLOBAL_STATE as GLOBAL
from stig_assessor.ui.web.api import route_request

LOG = Log("WebServer")

ASSETS_DIR = Path(__file__).parent / "assets"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    daemon_threads = True


class WebUIHandler(BaseHTTPRequestHandler):
    """Custom request handler for serving SPA and REST API."""

    def log_message(self, format: str, *args) -> None:
        """Override to use our logging system."""
        LOG.debug(f"{self.client_address[0]} - {format % args}")

    def _send_security_headers(self) -> None:
        """Inject standard security headers on every response."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        
        # Strict Air-Gap & XSS Defense Content-Security-Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        self.send_header("Content-Security-Policy", csp)
        
        # CORS restrictions (loopback only — include actual port)
        import builtins
        port = getattr(builtins, "_stig_web_port", 8080)
        self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{port}")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._send_security_headers()
        self.end_headers()

    def do_GET(self) -> None:
        """Serve static files."""
        # Route everything but /api to static files
        if self.path.startswith("/api/"):
            self.send_response(405)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"error","message":"Method not allowed"}')
            return

        # Simple static file serving
        req_path = self.path
        if req_path == "/" or req_path == "":
            req_path = "/index.html"

        # Security: prevent directory traversal
        req_path = req_path.lstrip("/")
        file_path = ASSETS_DIR / req_path

        try:
            # Check if it resolves within assets directory
            file_path.resolve().relative_to(ASSETS_DIR.resolve())
        except ValueError:
            self.send_response(403)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        if not file_path.exists() or not file_path.is_file():
            # Fallback to index.html for SPA routing if needed
            index_path = ASSETS_DIR / "index.html"
            if index_path.exists():
                file_path = index_path
            else:
                self.send_response(404)
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

        # Determine content type
        ext = file_path.suffix.lower()
        content_types = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".zip": "application/zip",
            ".woff2": "font/woff2",
        }
        content_type = content_types.get(ext, "application/octet-stream")

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            LOG.error(f"Error serving {file_path}: {e}")
            self.send_response(500)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

    def do_POST(self) -> None:
        """Handle API requests."""
        if not self.path.startswith("/api/"):
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"error","message":"Not found"}')
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > MAX_POST_PAYLOAD:
                self.send_response(413)
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(b'{"status":"error","message":"Payload too large"}')
                return

            try:
                with tempfile.SpooledTemporaryFile(max_size=5*1024*1024, mode="w+b") as sp_file:
                    bytes_read = 0
                    chunk_size = 64 * 1024
                    while bytes_read < content_length:
                        chunk = self.rfile.read(min(chunk_size, content_length - bytes_read))
                        if not chunk:
                            break
                        sp_file.write(chunk)
                        bytes_read += len(chunk)
                    
                    sp_file.seek(0)
                    payload = json.load(sp_file)
            except Exception:
                self.send_response(400)
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(b'{"status":"error","message":"Invalid JSON"}')
                return

            # Route the request to the api logic layer
            response_data = route_request(self.path, payload)

            status_code = 200 if response_data.get("status") == "success" else 400

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")

            response_json = json.dumps(response_data).encode("utf-8")
            self.send_header("Content-Length", str(len(response_json)))
            self._send_security_headers()
            self.end_headers()

            self.wfile.write(response_json)

        except Exception as e:
            LOG.error(f"Error handling POST {self.path}: {e}")
            self.send_response(500)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"status": "error", "message": f"Internal server error: {e}"}
                ).encode("utf-8")
            )


def start_server(port: int = 8080) -> None:
    """Start the web server with graceful shutdown support."""
    # Ensure assets directory exists for first run
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    httpd = None
    actual_port = port
    for attempt_port in range(port, port + 10):
        try:
            server_address = ("127.0.0.1", attempt_port)
            httpd = ThreadedHTTPServer(server_address, WebUIHandler)
            actual_port = attempt_port
            break
        except OSError as e:
            if attempt_port == port + 9:
                LOG.error(f"Failed to start web server on ports {port}-{port+9}: {e}")
                return
            continue

    if not httpd:
        return

    import builtins
    builtins._stig_web_port = actual_port
    LOG.info(f"Starting web server on http://localhost:{actual_port}/")

    # Graceful shutdown: poll GLOBAL_STATE.shutdown in a background thread
    def _shutdown_watcher():
        while not GLOBAL.shutdown.wait(timeout=0.5):
            pass
        LOG.info("Global shutdown signaled, stopping web server...")
        httpd.shutdown()

    watcher = threading.Thread(target=_shutdown_watcher, daemon=True)
    watcher.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down web server...")
        httpd.server_close()
    except Exception as e:
        LOG.error(f"Failed to run web server: {e}")
