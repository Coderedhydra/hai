from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .config import settings


REQUIRED_MANIFEST_FIELDS = [
    "authorizing_entity",
    "target_scope",  # list of allowed target patterns/hostnames
    "active_consent",  # bool; explicit consent required for active tests
    "created_at",  # epoch seconds
    "expires_at",  # epoch seconds
    "nonce",  # anti-replay
]


def canonicalize_manifest_for_signing(manifest: Dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for signing, excluding signature field."""
    manifest_no_sig = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(manifest_no_sig, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(obj: Dict[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(private_key, Ed25519PrivateKey)
    message = canonicalize_manifest_for_signing(obj)
    signature = private_key.sign(message)
    obj["signature"] = base64.b64encode(signature).decode("ascii")
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    obj.setdefault("public_key", base64.b64encode(public_key_bytes).decode("ascii"))
    return obj


def verify_manifest(manifest: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify manifest structure, signature, and expiration.

    Uses environment AUTH_PUBLIC_KEY_BASE64 if set; otherwise falls back to the
    manifest's embedded public_key (dev only).
    """
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            return False, f"missing required field: {field}"

    now = time.time()
    if float(manifest["expires_at"]) <= now:
        return False, "manifest expired"

    if float(manifest["created_at"]) > now + 300:
        return False, "manifest created_at is in the future"

    signature_b64 = manifest.get("signature")
    if not signature_b64:
        return False, "missing signature"

    configured_pub_b64 = settings.auth_public_key_base64
    manifest_pub_b64 = manifest.get("public_key")

    if configured_pub_b64:
        if not manifest_pub_b64 or manifest_pub_b64 != configured_pub_b64:
            return False, "manifest public_key does not match configured verifier key"
        public_key_raw = base64.b64decode(configured_pub_b64)
    else:
        # Dev fallback
        if not manifest_pub_b64:
            return False, "no public key available for verification"
        public_key_raw = base64.b64decode(manifest_pub_b64)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        signature = base64.b64decode(signature_b64)
        message = canonicalize_manifest_for_signing(manifest)
        public_key.verify(signature, message)
    except Exception as exc:  # noqa: BLE001
        return False, f"signature verification failed: {exc}"

    return True, "ok"


# ---------------------------- CLI for local dev ----------------------------- #


def cmd_gen_key(args: argparse.Namespace) -> int:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(out_dir, "public.b64"), "w") as f:
        f.write(base64.b64encode(public_raw).decode("ascii"))
    print(f"Wrote keys to: {out_dir}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    with open(args.key, "rb") as f:
        private_pem = f.read()
    with open(args.manifest, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    signed = sign_manifest(manifest, private_pem)
    out_path = os.path.abspath(args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, sort_keys=True)
    print(f"Signed manifest -> {out_path}")
    print("Public key (base64) embedded. Set AUTH_PUBLIC_KEY_BASE64 to enforce.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorization manifest tools")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen-key", help="Generate Ed25519 keypair")
    p_gen.add_argument("--out", required=True, help="Output directory for keys")
    p_gen.set_defaults(func=cmd_gen_key)

    p_sign = sub.add_parser("sign", help="Sign a manifest JSON file")
    p_sign.add_argument("--key", required=True, help="Path to private.pem")
    p_sign.add_argument("--manifest", required=True, help="Path to manifest JSON")
    p_sign.add_argument("--out", required=True, help="Output signed manifest path")
    p_sign.set_defaults(func=cmd_sign)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

