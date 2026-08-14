# Linux Daemons

`aurorad serve` and `aurorad issuer` are designed to run as independent
unprivileged system services. The supplied units use the `aurora` account,
dedicated persistent replay-state directories, strict file permissions, a
controlled restart policy, and process sandboxing. They listen only on
unprivileged ports, so they require no network-related capabilities.

## Install

Build or obtain the reviewed `aurorad` binary, then install it as root-owned:

```sh
install -o root -g root -m 0755 aurorad /usr/local/bin/aurorad
useradd --system --home-dir /var/lib/aurora --shell /usr/sbin/nologin aurora
install -d -o aurora -g aurora -m 0700 /etc/aurora
install -o root -g root -m 0644 deploy/systemd/aurorad-relay.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/systemd/aurorad-issuer.service /etc/systemd/system/
```

Copy the relevant example to its final name, replace every placeholder with
the deployment's verified values and paths, then make the file readable only
by the service account:

```sh
install -o aurora -g aurora -m 0600 deploy/systemd/relay.json.example /etc/aurora/relay.json
install -o aurora -g aurora -m 0600 deploy/systemd/issuer.json.example /etc/aurora/issuer.json
```

Each file is one JSON object with an `arguments` array. It is the sole
argument source: `--config` cannot be combined with command-line settings,
cannot recursively select another file, rejects unknown JSON fields, and is
opened as a regular owner-only file. It contains file paths and operational
settings, not private key contents.

All private key, access-hint, and replay-state inputs must be regular files
or directories owned by `aurora` with mode `0600` or `0700` as appropriate.
Public deployment objects may remain root-owned and readable by the service.
The units create `/var/lib/aurora-relay` and `/var/lib/aurora-issuer` with
mode `0700`; do not delete or replace their replay-state files while either
service is stopped or running.

Enable only the roles that the host serves:

```sh
systemctl daemon-reload
systemctl enable --now aurorad-relay.service
systemctl enable --now aurorad-issuer.service
systemctl status aurorad-relay.service aurorad-issuer.service
```

The units send `SIGTERM` during a normal stop and allow 20 seconds before the
service manager escalates. The daemon stops accepting work, closes active
relay state, and has a 15-second internal shutdown budget. Inspect failures
through the journal without echoing private configuration contents:

```sh
journalctl -u aurorad-relay.service -u aurorad-issuer.service --since today
```

Do not use the diagnostic `harness` command in either service unit.
