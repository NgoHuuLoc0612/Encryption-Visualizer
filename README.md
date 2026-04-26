# CryptoViz — Enterprise Encryption Visualizer

An enterprise-grade cryptographic visualization platform.
**C++ core engine** ↔ **pybind11** ↔ **Python FastAPI** ↔ **HTML/CSS/JS SPA**

---

## File Structure

| File                | Size  | Role |
|---------------------|-------|------|
| `crypto_core.hpp`   | 3.5K  | C++ data structures & public API declarations |
| `crypto_core.cpp`   | 20K   | Full C++ implementations (7 algorithms) |
| `bindings.cpp`      | 14K   | pybind11 module — all structs & functions exposed |
| `server.py`         | 13K   | FastAPI backend + Python analytics layer |
| `build.py`          | 2K    | Compile script (c++ → crypto_engine.so) |
| `index.html`        | 76K   | Complete frontend SPA (HTML/CSS/JS) |
| `requirements.txt`  | —     | Python dependencies |

---

## Algorithms (C++ Core)

| Algorithm | Standard | Features |
|-----------|----------|----------|
| **AES-128/192/256** | FIPS 197 | Full per-round state: SubBytes, ShiftRows, MixColumns, AddRoundKey; S-Box explorer; key schedule |
| **ChaCha20** | RFC 8439 | Column/diagonal quarter-round trace; keystream visualization |
| **SHA-256** | FIPS 180-4 | 64-round compression function; message schedule W[i]; H0–H7 tracking |
| **RSA** | PKCS#1 | Square-and-multiply modexp trace; key generation via extended GCD |
| **Diffie-Hellman** | RFC 3526 | Key exchange diagram; discrete log brute-force visualization; MITM simulation |
| **XOR Cipher** | — | Bitwise visualization; repeating-key; crib-drag attack panel |
| **Vigenère** | Classical | Per-character tableau; frequency analysis; Index of Coincidence |

## Python Analytics Layer (server.py)

- **Shannon Entropy** — byte distribution & efficiency meter
- **Avalanche Effect** — AES bit-flip analysis (C++ powered)
- **Frequency Analysis** — letter histogram + χ² vs English
- **Index of Coincidence** — key-length estimation for Vigenère
- **CTF Challenge Generator** — 3 difficulties, auto-scoring

---

## Setup & Run

### 1. Install Python dependencies
```bash
pip install fastapi uvicorn pybind11 pycryptodome
```

### 2. Build the C++ extension
```bash
python build.py
```
Requires: C++17 compiler (`g++`/`clang++`), Python dev headers, pybind11.

Produces: `build/crypto_engine.cpython-3XX.so` (copied to project root)

### 3. Start the server
```bash
python server.py
```
Open → **http://localhost:8000**

---

## API Reference

| Method | Endpoint | Body |
|--------|----------|------|
| GET | `/api/status` | — |
| POST | `/api/aes/encrypt` | `{plaintext_hex, key_hex, mode}` |
| GET | `/api/aes/stream` | `?plaintext_hex=…&key_hex=…` (SSE) |
| POST | `/api/chacha20/encrypt` | `{plaintext_hex, key_hex, nonce_hex, counter}` |
| POST | `/api/sha256/hash` | `{message_hex}` |
| POST | `/api/rsa/encrypt` | `{p, q, e, msg_hex}` |
| POST | `/api/dh/exchange` | `{p, g, alice_priv, bob_priv}` |
| POST | `/api/xor/encrypt` | `{plaintext_hex, key_hex}` |
| POST | `/api/vigenere/encrypt` | `{plaintext, key, encrypt}` |
| POST | `/api/analysis/avalanche` | `{plaintext_hex, key_hex, flip_bit_position}` |
| POST | `/api/analysis/entropy` | `{data_hex}` |
| POST | `/api/analysis/frequency` | `{text}` |
| POST | `/api/analysis/ioc` | `{ciphertext}` |
| POST | `/api/challenge/generate` | `{algorithm, difficulty}` |

---

## Frontend Features

- **9 algorithm tabs** with dedicated visualization panels
- **Animated step-by-step** play/pause/prev/next with speed control
- **Real-time SSE streaming** of AES rounds
- **Interactive S-Box grid** with hover substitution lookup
- **AES 4×4 state matrix** with color-coded operations
- **ChaCha20 4×4 state grid** with column/diagonal highlighting
- **SHA-256 compression function** with 64-round progress bar
- **Bitwise XOR visualizer** with binary representation
- **Vigenère tableau** with auto frequency analysis
- **DH exchange diagram** with discrete log brute-force trace
- **Avalanche meter** with byte-level diff visualization
- **CTF challenge system** with scoring and hint reveal
- **Entropy analyzer** with byte distribution chart
- **Index of Coincidence** with key-length bar chart

## Fallback Mode

If the C++ build fails, `server.py` uses `pycryptodome`/`hashlib` for basic crypto operations. Visualization depth is reduced (no per-round state). The frontend detects this via `/api/status`.
