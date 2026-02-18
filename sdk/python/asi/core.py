from __future__ import annotations

import json
import time
import hashlib
from pathlib import Path
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

import rfc8785  # JCS canonicalization

from .utils import (
    utf8_encode,
    uint64_be,
    concat_bytes,
    to_hex,
    from_hex,
    b64url_encode,
    b64url_decode,
    base58_encode,
    base58_decode,
)

ASI_VERSION = "0.1"
DOMAIN_TAG_PUBLISHER = "ASI-SKILL-MANIFEST/v0.1"
DOMAIN_TAG_INVOKE = "ASI-INVOKE/v0.1"
NULL_SEPARATOR = b"\x00"


# ─────────────────────────────────────────────
# Key & Identity
# ─────────────────────────────────────────────

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Returns (private_key_seed_32_bytes, public_key_32_bytes)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return private_bytes, public_bytes


def derive_identity(public_key: bytes) -> str:
    """
    Minimal DID:key (Ed25519) implementation.
    Multicodec prefix 0xed01.
    """
    if len(public_key) != 32:
        raise ValueError("Public key must be 32 bytes")

    multicodec = bytes([0xED, 0x01]) + public_key
    encoded = base58_encode(multicodec)
    return f"did:key:z{encoded}"


def public_key_from_identity(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("Invalid DID format")

    encoded = did[len("did:key:z") :]
    decoded = base58_decode(encoded)

    if len(decoded) < 2 or decoded[:2] != bytes([0xED, 0x01]):
        raise ValueError("Invalid multicodec prefix")

    public_key = decoded[2:]
    if len(public_key) != 32:
        raise ValueError(f"Invalid public key length in DID:key: {len(public_key)}")

    return public_key


# ─────────────────────────────────────────────
# Crypto primitives
# ─────────────────────────────────────────────

def sign(message: bytes, private_key_seed: bytes) -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
    return private_key.sign(message)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(public_key)
        public.verify(signature, message)
        return True
    except Exception:
        return False


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_display(digest: bytes) -> str:
    return f"sha256:{to_hex(digest)}"


def sha256_parse(display: str) -> bytes:
    if not display.startswith("sha256:"):
        raise ValueError("Invalid hash format")
    return from_hex(display[7:])


def canonicalize_json(obj: Any) -> bytes:
    """
    RFC 8785 JCS canonicalization
    """
    canonical = rfc8785.dumps(obj)
    if isinstance(canonical, bytes):
        return canonical
    return utf8_encode(canonical)


# ─────────────────────────────────────────────
# Signing Input Builders
# ─────────────────────────────────────────────

def build_publisher_signing_input(
    manifest_hash: bytes,
    signed_at: int,
) -> bytes:
    return concat_bytes([
        utf8_encode(DOMAIN_TAG_PUBLISHER),
        NULL_SEPARATOR,
        manifest_hash,
        uint64_be(signed_at),
    ])


def build_invocation_signing_input(
    agent_id: str,
    timestamp: int,
    payload_hash: bytes,
) -> bytes:
    return concat_bytes([
        utf8_encode(DOMAIN_TAG_INVOKE),
        NULL_SEPARATOR,
        utf8_encode(agent_id),
        NULL_SEPARATOR,
        uint64_be(timestamp),
        payload_hash,
    ])


def _enumerate_files(dir_path: Path, base: Path | None = None) -> list[str]:
    if base is None:
        base = dir_path

    results: list[str] = []
    for entry in dir_path.iterdir():
        st = entry.lstat()  # do not follow symlinks
        if entry.is_symlink():
            rel = entry.relative_to(base).as_posix()
            raise ValueError(f"Symlink detected and rejected: {rel}")
        if entry.is_dir():
            results.extend(_enumerate_files(entry, base))
        elif entry.is_file():
            results.append(entry.relative_to(base).as_posix())
    return results


def _is_valid_manifest_file_path(file_path: str) -> bool:
    if not isinstance(file_path, str) or len(file_path) == 0:
        return False
    if file_path.startswith("/") or file_path.endswith("/"):
        return False
    if "\\" in file_path or "\x00" in file_path:
        return False
    parts = file_path.split("/")
    return not any(part in ("", ".", "..") for part in parts)


def _is_within_bundle_root(bundle_path: Path, target_path: Path) -> bool:
    root = bundle_path.resolve()
    target = target_path.resolve()
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def hash_bundle(bundle_path: str) -> Dict[str, Dict[str, str]]:
    base = Path(bundle_path)
    all_files = _enumerate_files(base)
    files: Dict[str, str] = {}
    for rel in all_files:
        if rel.startswith("asi/") or rel == "manifest.json":
            continue
        content = (base / rel).read_bytes()
        files[rel] = sha256_display(sha256(content))
    return {"files": files}


def create_signed_manifest(
    manifest: Dict[str, Any],
    bundle_path: str,
    private_key_seed: bytes,
) -> Dict[str, Any]:
    full_manifest = {**manifest, **hash_bundle(bundle_path)}
    canonical_bytes = canonicalize_json(full_manifest)
    manifest_hash = sha256(canonical_bytes)

    signed_at = int(time.time())
    signing_input = build_publisher_signing_input(manifest_hash, signed_at)

    public_key = Ed25519PrivateKey.from_private_bytes(
        private_key_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = sign(signing_input, private_key_seed)

    return {
        "manifest": full_manifest,
        "signature": {
            "asi_version": ASI_VERSION,
            "publisher_id": derive_identity(public_key),
            "public_key": b64url_encode(public_key),
            "algorithm": "ed25519",
            "manifest_hash": sha256_display(manifest_hash),
            "signed_at": signed_at,
            "signature": b64url_encode(signature),
        },
    }


def verify_skill_bundle(bundle_path: str) -> Dict[str, Any]:
    base = Path(bundle_path)

    try:
        sig = json.loads((base / "asi" / "signature.json").read_text(encoding="utf-8"))
    except Exception:
        return {"status": "UNSIGNED", "publisherId": None, "errors": ["No asi/signature.json found"]}

    if sig.get("asi_version") != ASI_VERSION:
        return {
            "status": "UNKNOWN_VERSION",
            "publisherId": None,
            "errors": [f"Unrecognized asi_version: {sig.get('asi_version')}"],
        }

    if sig.get("algorithm") != "ed25519":
        return {
            "status": "TAMPERED",
            "publisherId": None,
            "errors": [f"Unsupported algorithm: {sig.get('algorithm')}"],
        }

    try:
        public_key = b64url_decode(sig["public_key"])
        if len(public_key) != 32:
            return {
                "status": "TAMPERED",
                "publisherId": None,
                "errors": [f"Invalid public key length: {len(public_key)}"],
            }
        derived = derive_identity(public_key)
        if derived != sig["publisher_id"]:
            return {
                "status": "TAMPERED",
                "publisherId": None,
                "errors": ["publisher_id does not match public_key"],
            }
    except Exception as e:
        return {"status": "TAMPERED", "publisherId": None, "errors": [f"Public key error: {e}"]}

    try:
        manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    except Exception as e:
        return {"status": "TAMPERED", "publisherId": None, "errors": [f"Cannot read manifest.json: {e}"]}

    if not isinstance(manifest, dict):
        return {"status": "TAMPERED", "publisherId": None, "errors": ["manifest.json must be an object"]}
    if not isinstance(manifest.get("files"), dict):
        return {"status": "TAMPERED", "publisherId": None, "errors": ["manifest.json must include files object"]}

    canonical_bytes = canonicalize_json(manifest)
    computed_hash = sha256(canonical_bytes)
    computed_hash_display = sha256_display(computed_hash)
    if computed_hash_display != sig.get("manifest_hash"):
        return {"status": "TAMPERED", "publisherId": None, "errors": ["manifest_hash does not match computed hash"]}

    try:
        signing_input = build_publisher_signing_input(computed_hash, int(sig["signed_at"]))
        signature_bytes = b64url_decode(sig["signature"])
    except Exception as e:
        return {"status": "TAMPERED", "publisherId": None, "errors": [f"Signature metadata error: {e}"]}

    if not verify(signing_input, signature_bytes, public_key):
        return {"status": "TAMPERED", "publisherId": None, "errors": ["Signature verification failed"]}

    try:
        bundle_files = _enumerate_files(base)
    except Exception as e:
        return {"status": "TAMPERED", "publisherId": None, "errors": [str(e)]}

    declared = set(manifest["files"].keys())
    for file_path in bundle_files:
        if file_path.startswith("asi/") or file_path == "manifest.json":
            continue
        if file_path not in declared:
            return {"status": "TAMPERED", "publisherId": None, "errors": [f"Undeclared file: {file_path}"]}

    for file_path, expected_hash in manifest["files"].items():
        if not _is_valid_manifest_file_path(file_path):
            return {"status": "TAMPERED", "publisherId": None, "errors": [f"Invalid manifest file path: {file_path}"]}
        if not isinstance(expected_hash, str):
            return {"status": "TAMPERED", "publisherId": None, "errors": [f"Invalid hash entry type for {file_path}"]}

        abs_path = base / file_path
        if not _is_within_bundle_root(base, abs_path):
            return {"status": "TAMPERED", "publisherId": None, "errors": [f"Path escapes bundle root: {file_path}"]}

        try:
            st = abs_path.lstat()
            if abs_path.is_symlink() or not abs_path.is_file():
                return {
                    "status": "TAMPERED",
                    "publisherId": None,
                    "errors": [f"Declared path is not a regular file: {file_path}"],
                }

            content = abs_path.read_bytes()
            actual_hash = sha256_display(sha256(content))
            if actual_hash != expected_hash:
                return {"status": "TAMPERED", "publisherId": None, "errors": [f"File hash mismatch: {file_path}"]}
        except Exception as e:
            return {
                "status": "TAMPERED",
                "publisherId": None,
                "errors": [f"Cannot read declared file {file_path}: {e}"],
            }

    return {"status": "VERIFIED", "publisherId": sig["publisher_id"], "errors": []}


# ─────────────────────────────────────────────
# Invocation Envelope
# ─────────────────────────────────────────────

def create_invocation_envelope(
    payload_body: bytes,
    content_type: str | None,
    private_key_seed: bytes,
) -> Dict[str, Any]:
    public_key = Ed25519PrivateKey.from_private_bytes(
        private_key_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    agent_id = derive_identity(public_key)
    timestamp = int(time.time())

    if content_type and "application/json" in content_type:
        try:
            parsed = json.loads(payload_body.decode("utf-8"))
            payload_to_hash = canonicalize_json(parsed)
        except Exception:
            payload_to_hash = payload_body
    else:
        payload_to_hash = payload_body

    payload_hash = sha256(payload_to_hash)

    signing_input = build_invocation_signing_input(
        agent_id,
        timestamp,
        payload_hash,
    )

    signature = sign(signing_input, private_key_seed)

    return {
        "asi_version": ASI_VERSION,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "payload_hash": sha256_display(payload_hash),
        "signature": b64url_encode(signature),
    }


def verify_invocation_envelope(
    envelope: Dict[str, Any],
    payload_body: bytes,
    content_type: str | None,
    max_skew: int = 300,
) -> Tuple[bool, str | None]:
    if envelope.get("asi_version") != ASI_VERSION:
        return False, None

    now = int(time.time())
    if abs(now - envelope["timestamp"]) > max_skew:
        return False, None

    if content_type and "application/json" in content_type:
        try:
            parsed = json.loads(payload_body.decode("utf-8"))
            payload_to_hash = canonicalize_json(parsed)
        except Exception:
            payload_to_hash = payload_body
    else:
        payload_to_hash = payload_body

    computed_hash = sha256(payload_to_hash)

    if sha256_display(computed_hash) != envelope["payload_hash"]:
        return False, None

    signing_input = build_invocation_signing_input(
        envelope["agent_id"],
        envelope["timestamp"],
        computed_hash,
    )

    public_key = public_key_from_identity(envelope["agent_id"])
    signature = b64url_decode(envelope["signature"])

    return verify(signing_input, signature, public_key), envelope["agent_id"]
