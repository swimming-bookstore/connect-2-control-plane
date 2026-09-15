# connect-2-control-plane

Rust replacement for a Teleport **auth + proxy** control plane. It speaks enough of the Teleport v16 wire protocol that:

- `teleport` agents can join with a token and open a reverse tunnel
- `tsh` can ping, log in, and use the **proxy subsystem** (`proxy:host:port@cluster`)
- TLS ALPN multiplexing on one port (web, gRPC auth, SSH proxy, reverse tunnel)

This is a compatibility control plane, not a full Teleport Enterprise clone (no MFA, RBAC graph, kube/db/app protocol plugins, or audit log).

## Run

```bash
cargo run -- --data-dir ./data --cluster-name connect2.local \
  --listen 0.0.0.0:3080 --public-addr 127.0.0.1:3080 \
  --admin-user admin --admin-pass adminadmin --join-token join-token
```

## Agent

```yaml
# /etc/teleport.yaml
version: v3
teleport:
  nodename: my-node
  data_dir: /var/lib/teleport
  auth_token: join-token
  proxy_server: 127.0.0.1:3080
  insecure_skip_verify: true
ssh_service:
  enabled: yes
auth_service:
  enabled: no
proxy_service:
  enabled: no
```

```bash
teleport start --config /etc/teleport.yaml
```

Join also works via HTTP:

`POST https://127.0.0.1:3080/webapi/host/credentials` with Teleport `RegisterUsingTokenRequest` JSON (`token`, `hostID`, `role`, `public_tls_key`, `public_ssh_key`).

## tsh

```bash
tsh login --proxy=127.0.0.1:3080 --user=admin --auth=local --insecure
# password: adminadmin
tsh ls
tsh ssh root@my-node
```

`tsh ssh` opens SSH to the proxy with ALPN `teleport-proxy-ssh` and requests subsystem `proxy:my-node:0@connect2.local`. The control plane dials the agent over `teleport-reversetunnel` using channel `teleport-transport` and request `teleport-transport-dial`.

## Protocol surface

| Path / ALPN | Role |
|---|---|
| `http/1.1`, `h2` | `/webapi/ping`, `/webapi/host/credentials`, `/webapi/ssh/certs` |
| `teleport-auth@`, `h2` | gRPC `proto.AuthService` (`Ping`, `GenerateHostCerts`, `UpsertNode`, `WatchEvents`, `ListResources`, …) |
| `teleport-proxy-ssh` | tsh / OpenSSH proxy, subsystem `proxy:` / `proxysites` / `sftp` |
| `teleport-reversetunnel` | agent reverse tunnel (`teleport-heartbeat`, `teleport-discovery`, `teleport-transport`) |

Server version is advertised as `16.4.3` so current Teleport clients accept the handshake.
