# ocs-tls-profiles API

Package `v1` defines the `TLSProfile` CRD and helpers for resolving and translating TLS configuration.

`TLSProfile` is a **namespace-scoped** resource.

## Concepts

```yaml
spec:
  rules:
    - selectors: [<selector>, ...]
      config:
        version: <TLSv1.2 | TLSv1.3>
        ciphers: [<cipher>, ...]
        groups:  [<group>, ...]
```

A `TLSProfile` contains an ordered list of **rules**. Each rule pairs one or more **selectors** with a **TLS config** (version, ciphers, groups). When a component looks up its config, the most specific matching selector wins.

**Selector** is a structured string of the form `domain/server` or just `domain`. The package enforces the format but is agnostic to what `domain` and `server` represent; their meaning is a contract between the CR author (admin) and the consuming code (operator/component) that calls `GetConfigForServer`.

**Selector forms** (most -> least specific):

| Form | Matches |
|------|---------|
| `example.io/s3` | server `s3` under `example.io` |
| `example.io` | all servers under `example.io` |
| `*.example.io/s3` | server `s3` under any subdomain of `example.io` |
| `*.example.io` | all servers under any subdomain of `example.io` |
| `*/s3` | server `s3` under any domain |
| `*` | everything |

**Version** is exact, not a range; `ValidateAndGetGoTLSConfig` sets both `MinVersion` and `MaxVersion` to the same value. This gives a strict "what you configure is what runs" guarantee, backed by the API-level enum and CEL rules that reject incompatible cipher/group combinations per version.

**TLS constraints enforced at the API level:**
- TLS 1.2: only TLS 1.2 ECDHE ciphers and classical groups (`secp256r1`, `secp384r1`, `secp521r1`, `X25519`).
- TLS 1.3: only TLS 1.3 ciphers; any group (classical or hybrid post-quantum).

**Notes for FIPS-enabled clusters (not enforced by the API):**
- Hybrid post-quantum groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) are not FIPS 140-2 approved.
- ChaCha20-Poly1305 ciphers are not FIPS 140-2 approved.

## Sample CR

```yaml
apiVersion: ocs.openshift.io/v1
kind: TLSProfile
metadata:
  name: cluster-tls
spec:
  rules:
    # Catch-all: TLS 1.2 for everything
    - selectors:
        - "*"
      config:
        version: TLSv1.2
        ciphers:
          - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        groups:
          - secp256r1
          - secp384r1

    # S3 gateway under storage.example.io: TLS 1.3 with post-quantum
    - selectors:
        - "storage.example.io/s3"
      config:
        version: TLSv1.3
        ciphers:
          - TLS_AES_128_GCM_SHA256
          - TLS_AES_256_GCM_SHA384
        groups:
          - X25519MLKEM768
          - secp256r1
```

## Usage

```go
import (
    tlsv1 "github.com/red-hat-storage/ocs-tls-profiles/api/v1"
)

// profile is a *tlsv1.TLSProfile fetched from the API server.

// 1. Resolve config for a specific component.
cfg, ok := tlsv1.GetConfigForServer(profile, "storage.example.io", "s3")
if !ok {
    // no rule matched - use a default
}

// 2. Validate and convert to a Go tls.Config (for Go TLS servers).
goTLS, err := tlsv1.ValidateAndGetGoTLSConfig(cfg)
if err != nil {
    // cipher/group incompatible with version
}
// goTLS has MinVersion, MaxVersion, CipherSuites, and CurvePreferences set.
// Merge it into your server's tls.Config or pass it to OpenSSLConfigFrom below.

// 3. Convert to OpenSSL strings (for Nginx, HAProxy, etc.).
ossl := tlsv1.OpenSSLConfigFrom(goTLS)
// ossl.Protocol -> "TLSv1.3"
// ossl.Ciphers  -> ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
// ossl.Groups   -> ["X25519MLKEM768", "prime256v1"]
```
