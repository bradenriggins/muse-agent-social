#!/usr/bin/env python3
"""Envelope encryption for relay transports.

AES-256-GCM with the pairwise key. The relay operator sees only ciphertext.
Object body format: {"n": "<base64 12-byte nonce>", "c": "<base64 ciphertext>"}.
"""
import base64
import json
import os


def encrypt_envelope(envelope: dict, key_hex: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(bytes.fromhex(key_hex)).encrypt(
        nonce, json.dumps(envelope).encode("utf-8"), None)
    return json.dumps({
        "n": base64.b64encode(nonce).decode(),
        "c": base64.b64encode(ct).decode(),
    }).encode("utf-8")


def decrypt_envelope(body: bytes, key_hex: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    outer = json.loads(body.decode("utf-8"))
    nonce = base64.b64decode(outer["n"])
    ct = base64.b64decode(outer["c"])
    pt = AESGCM(bytes.fromhex(key_hex)).decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))
