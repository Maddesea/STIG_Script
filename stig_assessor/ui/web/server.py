"""Native built-in web server for STIG Assessor UI."""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path

from stig_assessor.core.logging import Log
from stig_assessor.ui.web.api import route_request

LOG = Log("WebServer")

ASSETS_DIR = Path(__file__).parent / "assets"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    pass


class WebUIHandler(BaseHTTPRequestHandler):
    """Custom request handler for serving SPA and REST API."""

    def log_message(self, format: str, *args) -> None:
        """Override to use our logging system."""
        LOG.debug(f"{self.client_address[0]} - {format % args}")

    def do_GET(self) -> None:
        """Serve static files."""
        # Route everything but /api to static files
        if self.path.startswith("/api/"):
            self.send_response(405)
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
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

        # Determine content type
        ext = file_path.suffix.lower()
        content_types = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".svg": "image/svg+xml",
        }
        content_type = content_types.get(ext, "application/octet-stream")

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' data: 'unsafe-inline';")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            LOG.error(f"Error serving {file_path}: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

    def do_POST(self) -> None:
        """Handle API requests."""
        if not self.path.startswith("/api/"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"status":"error","message":"Not found"}')
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 50 * 1024 * 1024:  # 50MB limit
                self.send_response(413)
                self.end_headers()
                self.wfile.write(b'{"status":"error","message":"Payload too large"}')
                return

            post_data = self.rfile.read(content_length)

            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception:
                self.send_response(400)
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
            self.end_headers()

            self.wfile.write(response_json)

        except Exception as e:
            LOG.error(f"Error handling POST {self.path}: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"status": "error", "message": f"Internal server error: {e}"}
                ).encode("utf-8")
            )


def start_server(port: int = 8080) -> None:
    """Start the web server."""
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

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Shutting down web server...")
        httpd.server_close()
    except Exception as e:
        LOG.error(f"Failed to run web server: {e}")
