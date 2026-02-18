import json
import time

from asi import (
    generate_keypair,
    derive_identity,
    public_key_from_identity,
    sign,
    verify,
    sha256,
    sha256_display,
    build_publisher_signing_input,
    build_invocation_signing_input,
    create_invocation_envelope,
    verify_invocation_envelope,
)


def test_key_roundtrip():
    priv, pub = generate_keypair()
    did = derive_identity(pub)
    extracted = public_key_from_identity(did)
    assert extracted == pub


def test_sign_verify():
    priv, pub = generate_keypair()
    message = b"hello world"
    signature = sign(message, priv)
    assert verify(message, signature, pub) is True
    assert verify(b"tampered", signature, pub) is False


def test_sha256_display_roundtrip():
    digest = sha256(b"data")
    display = sha256_display(digest)
    assert display.startswith("sha256:")


def test_publisher_signing_input_layout():
    priv, pub = generate_keypair()
    digest = sha256(b"manifest")
    ts = 123456
    signing_input = build_publisher_signing_input(digest, ts)
    assert digest in signing_input


def test_invocation_signing_input_layout():
    priv, pub = generate_keypair()
    did = derive_identity(pub)
    digest = sha256(b"payload")
    ts = 123456
    signing_input = build_invocation_signing_input(did, ts, digest)
    assert digest in signing_input
    assert did.encode() in signing_input


def test_invocation_envelope_roundtrip():
    priv, pub = generate_keypair()
    payload = json.dumps({"a": 1}).encode("utf-8")

    envelope = create_invocation_envelope(
        payload,
        "application/json",
        priv,
    )

    valid, agent_id = verify_invocation_envelope(
        envelope,
        payload,
        "application/json",
    )

    assert valid is True
    assert agent_id == envelope["agent_id"]


def test_timestamp_skew_rejection():
    priv, pub = generate_keypair()
    payload = b"hello"

    envelope = create_invocation_envelope(
        payload,
        None,
        priv,
    )

    # simulate old timestamp
    envelope["timestamp"] = envelope["timestamp"] - 1000

    valid, _ = verify_invocation_envelope(
        envelope,
        payload,
        None,
        max_skew=100,
    )

    assert valid is False
