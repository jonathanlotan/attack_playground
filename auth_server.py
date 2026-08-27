import json
from http.server import HTTPServer, BaseHTTPRequestHandler


class AuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        response = json.dumps({
            "success": True,
            "authenticatedUsername": body.get("username", "guestuser"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.encode())

    def log_message(self, fmt, *args):
        print(fmt % args)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), AuthHandler).serve_forever()
