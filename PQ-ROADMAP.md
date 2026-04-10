# Post-Quantum Status

## Shipped: ML-KEM-768 + X25519 Hybrid (v1.3.0+)

Native post-quantum support via `HybridRecipient` / `HybridIdentity` in `pq.go`.

- **Algorithm**: ML-KEM-768 + X25519 (NIST FIPS 203 + Curve25519)
- **HPKE suite**: `MLKEM768X25519` via `filippo.io/hpke`
- **Stanza type**: `mlkem768x25519`
- **Key prefix**: `age1pq` (Bech32)
- **Label**: `"age-encryption.org/mlkem768x25519"` — enforces PQ-only mixing
- **Plugin**: `age-plugin-pq` for backward compat with older age implementations

## Usage

```go
import "github.com/luxfi/age"

// Generate PQ keypair
identity, _ := age.GenerateHybridIdentity()
recipient := identity.Recipient()

// Encrypt (PQ-safe)
w, _ := age.Encrypt(out, recipient)
w.Write(plaintext)
w.Close()

// Decrypt
r, _ := age.Decrypt(ciphertext, identity)
io.ReadAll(r)
```

## Security

- **Harvest-now-decrypt-later safe**: ML-KEM-768 protects against future quantum computers
- **Hybrid**: if ML-KEM is broken, X25519 still provides classical security
- **Anonymous**: attacker can't tell which recipient a message is encrypted to
- **Label enforcement**: PQ recipients can only be mixed with other PQ recipients (prevents downgrade)

## References

- LP-102: Encrypted SQLite Replication Standard
- NIST FIPS 203 (ML-KEM) — finalized August 2024
- `filippo.io/hpke` — HPKE with ML-KEM-768 + X25519
