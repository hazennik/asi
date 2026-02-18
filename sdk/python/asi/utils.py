from __future__ import annotations

import base64
from typing import Iterable

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def utf8_encode(s: str) -> bytes:
    return s.encode("utf-8")


def uint64_be(n: int) -> bytes:
    if n < 0:
        raise ValueError("uint64_be: n must be non-negative")
    # clamp to uint64 range (Python int is unbounded)
    if n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("uint64_be: n exceeds uint64")
    return int(n).to_bytes(8, byteorder="big", signed=False)


def concat_bytes(parts: Iterable[bytes]) -> bytes:
    return b"".join(parts)


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(h: str) -> bytes:
    if len(h) % 2 != 0:
        raise ValueError("from_hex: hex string must have even length")
    return bytes.fromhex(h)


def b64url_encode(data: bytes) -> str:
    """
    Base64url encoding (RFC 4648 §5) with no padding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """
    Base64url decoding (RFC 4648 §5) accepting missing padding.
    """
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode((s + ("=" * pad)).encode("ascii"))


def base58_encode(data: bytes) -> str:
    digits = [0]
    for byte in data:
        carry = byte
        for i in range(len(digits)):
            carry += digits[i] << 8
            digits[i] = carry % 58
            carry //= 58
        while carry > 0:
            digits.append(carry % 58)
            carry //= 58

    result = ""
    for b in data:
        if b == 0:
            result += "1"
        else:
            break

    for d in reversed(digits):
        result += BASE58_ALPHABET[d]
    return result


def base58_decode(s: str) -> bytes:
    out = []
    for ch in s:
        carry = BASE58_ALPHABET.find(ch)
        if carry < 0:
            raise ValueError(f"Invalid base58 character: {ch}")

        for i in range(len(out)):
            carry += out[i] * 58
            out[i] = carry & 0xFF
            carry >>= 8

        while carry > 0:
            out.append(carry & 0xFF)
            carry >>= 8

    for ch in s:
        if ch == "1":
            out.append(0)
        else:
            break

    return bytes(reversed(out))
