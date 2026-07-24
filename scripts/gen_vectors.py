#!/usr/bin/env python3
"""Generate cross-implementation test vectors (DoD).

Produced with pyca/cryptography (OpenSSL) as the implementation independent
of the client's @noble/post-quantum; consumed by client/tests/vectors.test.ts
(pyca cryptography stands in for liboqs as the reference implementation).

Run with the server venv:  server/.venv/Scripts/python scripts/gen_vectors.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

ROOT = Path(__file__).resolve().parent.parent
VECTOR_COUNT = 8


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def gen_mlkem() -> dict[str, Any]:
    vectors = []
    for _ in range(VECTOR_COUNT):
        key = MLKEM768PrivateKey.generate()
        seed = key.private_bytes_raw()  # FIPS 203 64-byte (d || z) seed
        ss, ct = key.public_key().encapsulate()
        vectors.append(
            {
                "seed": b64(seed),
                "pk": b64(key.public_key().public_bytes_raw()),
                "ct": b64(ct),
                "ss": b64(ss),
            }
        )
    return {
        "algorithm": "ML-KEM-768 (FIPS 203)",
        "source": "pyca cryptography 49.0.0 / OpenSSL",
        "check": "keygen(seed) must reproduce pk; decapsulate(ct, sk) must equal ss",
        "vectors": vectors,
    }


def gen_mldsa() -> dict[str, Any]:
    vectors = []
    for i in range(VECTOR_COUNT):
        key = MLDSA65PrivateKey.generate()
        seed = key.private_bytes_raw()  # FIPS 204 32-byte xi seed
        message = os.urandom(17 + i * 13)
        vectors.append(
            {
                "seed": b64(seed),
                "pk": b64(key.public_key().public_bytes_raw()),
                "msg": b64(message),
                "sig": b64(key.sign(message)),
            }
        )
    return {
        "algorithm": "ML-DSA-65 (FIPS 204)",
        "source": "pyca cryptography 49.0.0 / OpenSSL",
        "check": "keygen(seed) must reproduce pk; verify(sig, msg, pk) must pass; tampered must fail",
        "vectors": vectors,
    }


def main() -> int:
    out_dir = ROOT / "shared" / "vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ml-kem-768.json").write_text(json.dumps(gen_mlkem(), indent=2) + "\n")
    (out_dir / "ml-dsa-65.json").write_text(json.dumps(gen_mldsa(), indent=2) + "\n")
    print(f"wrote {VECTOR_COUNT} vectors each to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
