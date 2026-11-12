# A stand-in Headscale for working on the web interface: serves one policy file
# and a few made-up devices and users. See docs/web-service.md, Development.
#   python3 scripts/fake_headscale.py 18475 policy.hujson
import json, sys, http.server, pathlib
policy = pathlib.Path(sys.argv[2]).read_text()
nodes = {"nodes": [
  {"id": "1", "givenName": "alice-mbp", "user": {"name": "alice", "email": "alice@example.com"}, "ipAddresses": ["100.64.0.1", "fd7a:115c:a1e0::1"], "online": True},
  {"id": "2", "givenName": "bob-laptop", "user": {"name": "bob", "email": "bob@example.com"}, "ipAddresses": ["100.64.0.2"], "online": False, "lastSeen": "2026-11-09T08:15:02Z"},
  {"id": "3", "givenName": "web-1", "tags": ["tag:web"], "ipAddresses": ["100.64.0.10"], "online": True},
  {"id": "4", "givenName": "db-1", "tags": ["tag:db", "tag:prod"], "ipAddresses": ["100.64.0.11"], "online": True},
  {"id": "5", "givenName": "exit-ams", "tags": ["tag:exit"], "ipAddresses": ["100.64.0.12"], "online": True,
   "availableRoutes": ["0.0.0.0/0", "::/0", "192.168.10.0/24"], "approvedRoutes": ["0.0.0.0/0", "::/0", "192.168.10.0/24"]}]}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/api/v1/policy": {"policy": policy}, "/api/v1/node": nodes, "/api/v1/user": {"users": [{"id": str(i), "name": n, "email": f"{n}@example.com"} for i, n in enumerate(["alice", "bob", "carol"], 1)]}}.get(self.path.split("?")[0])
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(body or {"message": "not found"}).encode())
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
