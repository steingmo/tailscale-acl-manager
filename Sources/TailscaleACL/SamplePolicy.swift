import Foundation

enum SamplePolicy {
    static let text = """
{
  // Example Tailscale ACL policy. Edit freely — everything updates live.
  "groups": {
    "group:eng":      ["alice@example.com", "bob@example.com"],
    "group:ops":      ["carol@example.com"],
    "group:contract": ["dave@partner.com"],
  },

  "tagOwners": {
    "tag:server": ["group:ops"],
    "tag:db":     ["group:ops"],
    "tag:ci":     ["group:eng"],
    "tag:web":    ["group:ops"],
  },

  "hosts": {
    "office-router": "100.64.0.1",
    "internal-net":  "10.0.0.0/16",
  },

  "acls": [
    // Engineers reach app + CI servers over SSH and web ports.
    {
      "action": "accept",
      "src":    ["group:eng"],
      "dst":    ["tag:server:22,80,443", "tag:ci:22,8080"],
    },

    // Ops can reach everything.
    {
      "action": "accept",
      "src":    ["group:ops"],
      "dst":    ["*:*"],
    },

    // Web servers may talk to the database on Postgres only.
    {
      "action": "accept",
      "src":    ["tag:web"],
      "dst":    ["tag:db:5432"],
    },

    // Contractors get HTTPS to app servers, nothing else.
    {
      "action": "accept",
      "src":    ["group:contract"],
      "dst":    ["tag:server:443"],
    },

    // Everyone on the tailnet can use the office router for DNS.
    {
      "action": "accept",
      "src":    ["autogroup:members"],
      "dst":    ["office-router:53"],
    },
  ],

  "grants": [
    // Modern grant syntax: engineers may use Redis on the db server.
    {
      "src": ["group:eng"],
      "dst": ["tag:db"],
      "ip":  ["tcp:6379"],
    },
  ],

  "tests": [
    {
      "src":    "alice@example.com",
      "accept": ["tag:server:22", "tag:ci:8080", "tag:db:6379"],
      "deny":   ["tag:db:5432"],
    },
    {
      "src":    "dave@partner.com",
      "accept": ["tag:server:443"],
      "deny":   ["tag:server:22", "tag:ci:22"],
    },
    {
      "src":    "carol@example.com",
      "accept": ["tag:db:5432", "tag:server:22"],
    },
  ],
}
"""
}
