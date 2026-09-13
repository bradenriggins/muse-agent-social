#!/usr/bin/env python3
"""R2 (S3-compatible) transport backend for the agent social layer.

Slot layout mirrors the local relay inside one bucket per pair:

    to-<slot>/incoming/<timestamp>-<envelope-id>.json
    to-<slot>/consumed/...
    to-<slot>/quarantine/...

Envelope bodies are AES-256-GCM encrypted with the pairwise HMAC key before
upload, so the bucket operator sees only ciphertext. Object body format:

    {"n": "<base64 12-byte nonce>", "c": "<base64 ciphertext>"}

Requires boto3 and cryptography (see ~/workspace/agent-social/.venv).
"""
import base64
import json
import os


def _boto3_client(endpoint, access_key_id, secret_access_key):
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name="auto",
    )


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


class R2Backend:
    def __init__(self, endpoint, bucket, access_key_id, secret_access_key):
        self.bucket = bucket
        self.s3 = _boto3_client(endpoint, access_key_id, secret_access_key)

    def _key(self, slot, subdir, fname):
        return f"to-{slot}/{subdir}/{fname}"

    def put_incoming(self, slot, fname, payload: bytes):
        self.s3.put_object(Bucket=self.bucket,
                           Key=self._key(slot, "incoming", fname), Body=payload)

    def list_incoming(self, slot):
        prefix = f"to-{slot}/incoming/"
        out, token = [], None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": prefix, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            resp = self.s3.list_objects_v2(**kw)
            out.extend(o["Key"][len(prefix):] for o in resp.get("Contents", ()))
            if not resp.get("IsTruncated"):
                break
            token = resp["NextContinuationToken"]
        return sorted(out)

    def read(self, slot, subdir, fname) -> bytes:
        return self.s3.get_object(
            Bucket=self.bucket, Key=self._key(slot, subdir, fname))["Body"].read()

    def move(self, slot, fname, from_subdir, to_subdir):
        src = {"Bucket": self.bucket, "Key": self._key(slot, from_subdir, fname)}
        self.s3.copy_object(Bucket=self.bucket,
                            Key=self._key(slot, to_subdir, fname), CopySource=src)
        self.s3.delete_object(Bucket=self.bucket, Key=src["Key"])

    def write_reason(self, slot, fname, reason: str):
        self.s3.put_object(Bucket=self.bucket,
                           Key=self._key(slot, "quarantine", fname + ".reason.txt"),
                           Body=(reason + "\n").encode())
