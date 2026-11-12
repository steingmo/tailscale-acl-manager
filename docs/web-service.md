# Web service

`tailscale-acl serve` is a read-only web service for colleagues on any
platform: they sign in with Microsoft and see a tailnet's Access Map, run the
Simulator, and read its problems, policy, and devices. It never changes a
policy — editing and pushing stay in the Mac app.

Every view has its own address (`/s/<tailnet>/map?focus=group:eng`,
`/s/<tailnet>/simulate?src=…&dst=…&port=443`, `/s/<tailnet>/policy?line=23`),
so a link to a finding or a simulation can be sent to a colleague.

It is built on Linux (or on a Mac with `TAILSCALE_ACL_ENGINE=1`); the Mac app
does not contain it.

## What it needs

1. **A Microsoft Entra ID app registration** (Entra admin center ▸ App
   registrations ▸ New registration):
   - Supported accounts: this organization only.
   - Redirect URI: platform **Web**, `https://<your address>/auth/callback`.
   - Certificates & secrets ▸ New client secret. Save the value in a file
     only the service's account can read.
   - App roles ▸ create `Viewer` and `Approver` (allowed member types:
     users/groups). Then, under Enterprise applications ▸ this app ▸ Users
     and groups, assign people or groups to them. (Assigning groups needs
     Entra ID P1; otherwise assign people, or list group object IDs under
     `roles` below and add the groups claim to the ID token.)
   - Note the **Directory (tenant) ID** and the **Application (client) ID**.
2. **A credential per tailnet, read-only.** Tailscale: an OAuth client with
   the read scopes for the policy file, devices, and users
   (`policy_file:read`, `devices:core:read`, `users:read`). Headscale: an API
   key. Each in its own file.
3. **A TLS proxy in front**, because the service listens on the loopback
   address with plain HTTP. On a machine in the tailnet, `tailscale serve`
   does this and gives the address and certificate.

## Config

```json
{
  "listen": "127.0.0.1:8080",
  "publicURL": "https://acl.example.ts.net",
  "dataDir": "/var/lib/tailscale-acl",
  "entra": {
    "tenant": "<directory (tenant) ID>",
    "clientID": "<application (client) ID>",
    "clientSecretFile": "/etc/tailscale-acl/entra-secret"
  },
  "roles": { "viewer": ["Viewer"], "approver": ["Approver"] },
  "sources": [
    { "id": "prod", "name": "Production", "kind": "tailscale", "tailnet": "-",
      "credentialFile": "/etc/tailscale-acl/prod-key" },
    { "id": "lab", "name": "Lab", "kind": "headscale", "serverURL": "https://headscale.example.com",
      "credentialFile": "/etc/tailscale-acl/lab-key" }
  ]
}
```

`roles` lists which values of the ID token's `roles` claim (app roles) or
`groups` claim (group object IDs) give each role. Approvers are viewers too;
someone with neither is refused.

```sh
tailscale-acl serve --config /etc/tailscale-acl/server.json --check   # check the config and exit
tailscale-acl serve --config /etc/tailscale-acl/server.json
```

## Installing on Ubuntu

Tested on Ubuntu 26.04 (a Proxmox LXC container, 2 cores, 2 GB RAM).

1. Install Swift for your Ubuntu from swift.org (check the signature), and
   copy or clone this repository onto the server.
2. As root, from the repository: `deploy/install.sh`. It builds a release
   binary (several minutes the first time) with Swift's libraries linked in,
   installs `/usr/local/bin/tailscale-acl`, creates the `tailscale-acl`
   account, `/etc/tailscale-acl/` (root-owned, readable by that account
   only), the systemd unit, and monthly rotation of the audit log. Run it
   again to update.
3. Write `/etc/tailscale-acl/server.json` from `server.json.example`, and the
   secret files it names, each `0640 root:tailscale-acl`. Check it:
   `tailscale-acl serve --config /etc/tailscale-acl/server.json --check`.
4. `systemctl enable --now tailscale-acl`. It listens on 127.0.0.1:8080.
5. HTTPS in front. With a Tailscale tailnet: join the server to it, turn on
   HTTPS certificates for the tailnet (admin console ▸ DNS), and
   `tailscale serve --bg 8080`; the address is
   `https://<machine>.<tailnet>.ts.net`, which goes into `publicURL` and the
   Entra redirect URI. (Headscale can't issue those certificates; use a
   reverse proxy with a certificate of your own there.)

The unit is locked down (`systemd-analyze security tailscale-acl` rates it
1.4, "OK"): its own account, no capabilities, a read-only system except
`/var/lib/tailscale-acl`, IP and Unix sockets only, a system-call filter.
Back up `/var/lib/tailscale-acl` (the audit log) and `/etc/tailscale-acl`
— on Proxmox, the container's scheduled backup covers both.

## How signing in works

OpenID Connect authorization code flow with PKCE, as a confidential client.
The browser is sent to Microsoft; the code that comes back is traded for an
ID token server to server, with the client secret. The token must be from the
configured tenant, for this application, unexpired, and carry the nonce of
this sign-in; the sign-in must finish in the browser that started it. The
session is a random ID in an `HttpOnly`, `SameSite=Lax`, `Secure` cookie,
kept in memory for 8 hours — a restart signs everyone out.

The ID token's signature is not verified: the token is only ever received
directly from Microsoft's token endpoint over TLS, for which OpenID Connect
Core (§3.1.3.7) permits relying on TLS instead. See `EntraLogin.validate`.

## API (signed in, role viewer)

| | |
|---|---|
| `GET /api/me` | who is signed in, and their roles |
| `GET /api/sources` | the configured tailnets |
| `GET /api/sources/{id}/policy` | the policy text, whether it parses, when it was read |
| `GET /api/sources/{id}/problems` | lint and security findings, with lines |
| `GET /api/sources/{id}/devices` | devices |
| `GET /api/sources/{id}/simulate?src=&dst=&port=&proto=` | whether src reaches dst, and through which rules; `node:<device id>` picks a device |
| `GET /api/sources/{id}/map?focus=&direction=reaches\|reachedBy` | the Access Map for one entity or `node:<device id>` |
| `GET /api/sources/{id}/entities` | users, groups, tags, hosts, IP sets, autogroups — for pickers |

A tailnet's policy and devices are read at most once a minute.

## Audit log

`<dataDir>/audit.jsonl`, one JSON object per line, readable by the service's
account only: sign-ins (and why one failed), sign-outs, refusals, and every
API request with who made it. No secrets or tokens.

## Development

```json
{ "listen": "127.0.0.1:8080", "publicURL": "http://localhost:8080", "dataDir": "/tmp/tsacl",
  "devLogin": { "login": "me@example.com", "roles": ["viewer"] },
  "sources": [ … ] }
```

`devLogin` signs everyone in without Microsoft. It is refused unless the
address is localhost **and** `--insecure-dev-login` is given.

To work on the interface without a tailnet, `scripts/fake_headscale.py`
serves a policy file and a few devices as a Headscale server would; point a
source at it:

```sh
python3 scripts/fake_headscale.py 18475 my-policy.hujson &
# source: {"id": "lab", "name": "Lab", "kind": "headscale",
#          "serverURL": "http://127.0.0.1:18475", "credential": "unused"}
TAILSCALE_ACL_ENGINE=1 swift run TailscaleACL serve --config dev.json --insecure-dev-login
```

The interface is `Sources/TailscaleACL/Server/Web/` — plain HTML, CSS, and
JavaScript with no build step and no outside code, compiled into the binary.
Rebuild to see a change.
