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
provisioning `wallet.bin` with one-time entries, a lab TLS CA hierarchy, and a
`manifest.json` describing the layout and public endpoints.

The TLS material is a two-level lab hierarchy:

- `ca.pem` / `ca-key.pem`: the self-signed lab CA (`CA:TRUE`, cert-sign usage,
  CN "auroralab lab CA (local lab testing only)"). **`ca.pem` is what lab
  client devices install as a trust anchor** — Android's user trust store
  requires a CA certificate, so installing the leaf alone does not work.
- `tls-cert.pem` / `tls-key.pem`: the relay/issuer leaf certificate signed by
  the lab CA, with SANs covering `--relay-host`. `tls-cert.pem` carries the
  full chain (leaf first, then the CA) so both endpoints present a chain that
  validates against `ca.pem`. `auroralab serve` fails closed at load time if
  the chain does not verify against `ca.pem` or if the CA is not a
  certificate-signing CA.

The cover template continues to pin the **leaf** subject public key info
(`OriginSPKIHash`), not the CA; the CA hierarchy change does not affect that
binding or the relay handshake.

`--relay-host` is the address clients will dial (e.g. the lab machine's LAN IP
for a phone client); it is embedded in the wallet URLs and TLS SANs.

## Export a provisioning code for a client app

```sh
go run ./cmd/auroralab import-code --dir /path/to/lab   # or --wallet /path/to/wallet.bin
```

This wraps the minted `wallet.bin` in the mobile-FFI import envelope
(`uint32-BE sourceLength || source || uint8 spentKeyCount || count×48-byte
spent hint keys`, zero spent keys — the format is exported from the `client`
package as `EncodeNativeProvisioningImportEnvelope` /
`DecodeNativeProvisioningImportEnvelope`), prints the canonical base64
provisioning code for the app's "import provisioning code" field, and writes
it owner-only to `import-code.txt` beside the wallet. The envelope limits
(16 MiB source, 64 spent keys, 48-byte keys) are pinned to the Android
parser's constants by `cmd/auroralab/import_code_test.go`.

## Serve the lab deployment

```sh
go run ./cmd/auroralab serve --dir /path/to/lab --listen 127.0.0.1:9443
```

The relay first hop and its bound Blind RSA issuer backend are served from the
minted material; an in-process loopback cover origin doubles as an end-to-end
egress target. The listen port must match the minted wallet port (the host may
differ, e.g. `--listen 0.0.0.0:9443`). Non-loopback binding requires
`--allow-non-loopback` and prints a warning; the default remains loopback.

The presented chain can be verified exactly as a client device would:

```sh
echo Q | openssl s_client -connect 127.0.0.1:9444 -CAfile /path/to/lab/ca.pem \
    -verify_return_error
curl --cacert /path/to/lab/ca.pem https://127.0.0.1:9443/
```

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
real host install `ca.pem` into that store (on Android, install it as a user
CA certificate). The in-repo acceptance test
(`cmd/aurorac/auroralab_proxy_test.go`) and the library-level end-to-end test
(`internal/labfixture/integration_test.go`) demonstrate the full flow on a
development host trusting exactly `ca.pem`.
