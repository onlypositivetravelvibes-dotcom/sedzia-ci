#!/usr/bin/env python3
"""Offline M14 DSSE signer. Private key input is never copied into the package."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKAGE / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m14_attestation import PAYLOAD_TYPE, pae
from m14_common import canonical, safe_id, sha256_bytes


def build_envelope(body: dict, private_key: Ed25519PrivateKey) -> dict:
    if not isinstance(body, dict):
        raise ValueError("BODY_NOT_OBJECT")
    safe_id(body.get("statement_id"), "statement_id")
    public_raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyid = sha256_bytes(public_raw)[:16]
    if body.get("issuer_ref") != keyid:
        raise ValueError("ISSUER_KEYID_MISMATCH")
    raw = canonical(body)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(private_key.sign(pae(PAYLOAD_TYPE, raw))).decode("ascii")}],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--body", type=Path, required=True)
    ap.add_argument("--private-key", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if args.out.exists() or args.out.is_symlink():
        print(json.dumps({"status": "HOLD", "reason": "OUTPUT_EXISTS"}, sort_keys=True))
        return 2
    body = json.loads(args.body.read_text(encoding="utf-8"))
    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("NOT_ED25519_PRIVATE_KEY")
    envelope = build_envelope(body, private_key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(envelope, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"status": "SIGNED", "statement_id": body["statement_id"], "keyid": envelope["signatures"][0]["keyid"], "out": str(args.out)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
