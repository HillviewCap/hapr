"""Simple echo HTTP server for HAProxy backend testing.
Returns request details as JSON so we can verify proxying works."""

import json
import http.server
import socketserver
from datetime import datetime, timezone

class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        response = {
            "service": "hapr-echo-backend",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "client_address": self.client_address[0],
        }
        body = json.dumps(response, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        response = {
            "service": "hapr-echo-backend",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "body": post_body[:4096],
            "client_address": self.client_address[0],
        }
        body = json.dumps(response, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.write(body)

    # Actual write helper
    def write(self, data):
        self.wfile.write(data)

    def log_message(self, format, *args):
        print(f"[echo] {self.client_address[0]} - {format % args}")

if __name__ == "__main__":
    PORT = 8080
    with socketserver.TCPServer(("0.0.0.0", PORT), EchoHandler) as httpd:
        print(f"Echo server listening on port {PORT}")
        httpd.serve_forever()
