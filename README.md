# Aegis Gulf Compliance Kernel — C++20 (v0.1.0)

**AES-256-GCM authenticated encryption + SHA-256 HMAC audit chain**
POPIA Section 19 compliant — South Africa

---

## Build and Run (Ubuntu / Debian)

```bash
# Install dependencies
sudo apt-get install -y build-essential cmake libssl-dev

# Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# Run benchmark (10,000 encrypted archive operations)
./build/aegis_benchmark 10000

# Run larger benchmark
./build/aegis_benchmark 100000
```

## Build and Run (Alpine Linux / Docker)

```bash
docker build -f Dockerfile.cpp -t aegisgulf/kernel-cpp:0.1.0 .
docker run aegisgulf/kernel-cpp:0.1.0 50000
```

---

## What this kernel does

Every call to `archive()`:

1. **AES-256-GCM encrypts** the payload using a fresh random 12-byte nonce
2. **Computes a SHA-256 HMAC** that chains to the previous entry
3. **Appends the entry** to an append-only vault

Any modification to any entry — even a single bit — breaks the SHA-256 HMAC chain from that point forward. The `verify_chain()` method detects this mathematically and identifies the exact corrupted entry.

---

## Cryptographic implementation

| Component | Implementation |
|-----------|----------------|
| Encryption | AES-256-GCM via OpenSSL 3.x EVP API |
| Hardware acceleration | Intel AES-NI / ARMv8 Crypto Extensions (automatic via OpenSSL) |
| Integrity | SHA-256 HMAC via `HMAC(EVP_sha256(), ...)` |
| Chain comparison | `CRYPTO_memcmp()` — constant-time, prevents timing attacks |
| Nonce generation | `RAND_bytes()` — CSPRNG |
| Key generation | `RAND_bytes()` — 256-bit, separate keys for encryption and HMAC |

---

## C++20 features used

| Feature | Usage |
|---------|-------|
| `std::span` | Zero-copy views over byte buffers in encrypt/decrypt paths |
| `std::expected` | Error handling without exceptions in cryptographic functions |
| Concepts | `ByteRange` concept constrains buffer parameters |
| `std::format` | JSON envelope construction and log formatting |
| `std::atomic` | Lock-free statistics counters |
| `std::shared_mutex` | Reader-writer lock for concurrent vault access |

---

## POPIA compliance mapping

| POPIA Section | Control | Evidence produced |
|---------------|---------|-------------------|
| Section 19 — Security safeguards | AES-256-GCM encryption per entry | Encryption audit reports |
| Section 19 — Integrity | SHA-256 HMAC chain | Chain verification report |
| Section 22 — Breach notification | Anomaly events archived | Notification audit trail |
| Section 14 — Retention | Append-only vault | Retention log export |

---

## Honest status (v0.1.0)

This is the **initial C++20 kernel implementation**. It is a working,
compilable, testable codebase — not a promise.

What works today:
- AES-256-GCM encryption and decryption (OpenSSL EVP API)
- SHA-256 HMAC audit chain with constant-time verification
- Append-only vault with thread-safe concurrent access
- Live throughput benchmark binary
- Docker container (Alpine, multi-stage build)

What is in development:
- HTTP/gRPC REST API server (equivalent to the Python `server.py`)
- Kafka/RabbitMQ stream ingestion
- WORM storage backend adapters (AWS S3 Object Lock, Azure Blob)
- Data Subject Rights portal integration

The Python repository (`aegis-gulf-kernel`) remains the reference
implementation for the REST API layer while the C++ HTTP server is built.

---

## Reference: Python prototype

The Python implementation at `github.com/Cybertronvula/aegis-gulf-kernel`
produces **identical cryptographic guarantees** using the same algorithms
(via Python's `cryptography` library, which wraps OpenSSL).

Python prototype is used for:
- Live API demonstrations (`aegis-gulf-kernel.onrender.com`)
- Rapid iteration on REST API design
- Client due diligence and benchmark verification

C++ kernel is used for:
- Production deployment (this repository)
- Hardware AES-NI acceleration
- Zero-copy memory architecture
- Sub-microsecond per-entry latency

---

**Aegis Gulf — Kimberley, Northern Cape, South Africa**
*Securing the Future*
