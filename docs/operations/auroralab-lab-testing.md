# auroralab — LOCAL LAB TESTING ONLY

**`auroralab` mints and serves self-contained, self-signed lab deployments so
production clients can be exercised end to end on a lab network. It MUST never
be deployed as production infrastructure, and its output MUST never be reused
outside a disposable lab deployment. It is intentionally absent from the main
README's production command list.**

## Mint a lab deployment

```sh
go run ./cmd/auroralab mint --dir /path/to/lab [--relay-host 192.168.1.20] \
    [--relay-port 9443] [--issuer-port 9444] [--entries 8] [--validity 24h]
```

This writes an owner-only (`0700` directory, `0600` files) deployment with a
relay descriptor and epoch signing keys, a signed cover template and template
authority, issuer metadata plus its Blind RSA key, a signed-seed trust anchor,
a sealed v2 native provisioning trust file (`native-provisioning-trust.bin`,
independently verifiable with
`go run ./cmd/auroractl check-native-provisioning-trust`), a native
provisioning `wallet.bin` with one-time entries, a shared self-signed TLS
certificate covering the relay/issuer host, and a `manifest.json` describing
the layout and public endpoints.

`--relay-host` is the address clients will dial (e.g. the lab machine's LAN IP
for a phone client); it is embedded in the wallet URLs and TLS SANs.

## Serve the lab deployment

```sh
go run ./cmd/auroralab serve --dir /path/to/lab --listen 127.0.0.1:9443
```

The relay first hop and its bound Blind RSA issuer backend are served from the
minted material; an in-process loopback cover origin doubles as an end-to-end
egress target. The listen port must match the minted wallet port (the host may
differ, e.g. `--listen 0.0.0.0:9443`). Non-loopback binding requires
`--allow-non-loopback` and prints a warning; the default remains loopback.

## Client

Any production client that accepts a native provisioning wallet plus a
signed-seed trust configuration can use the minted pair. For `aurorac`
(Linux-only):

```sh
aurorac proxy --provisioning-wallet /path/to/lab/wallet.bin \
    --wallet-state /path/to/lab/wallet-state.bin \
    --signed-seed-roots /path/to/lab/native-provisioning-trust.bin
```

Then point a client at the printed SOCKS5/HTTP-CONNECT listeners; a request to
the printed `cover=` address proves the full chain (wallet reservation →
handshake → live Blind RSA issuer exchange → relay egress).

Note: `aurorac`'s issuer HTTP client trusts the system root store only, so on a
real host the minted issuer certificate must be added to that store (or the
issuer exchange fronted accordingly). The in-repo acceptance test
(`cmd/aurorac/auroralab_proxy_test.go`) and the library-level end-to-end test
(`internal/labfixture/integration_test.go`) demonstrate the full flow on a
development host using the minted certificate directly.
