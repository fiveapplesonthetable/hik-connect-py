"""
hik_ecdh.py — pure-Python implementation of the
EZVIZECDHCrypter::ezviz_ecdh_encECDHReqPackage / decECDHReqPackage layer
reverse-engineered from libezstreamclient.so (Hik-Connect 4.19).

All wire-format details are in docs/ecdh_layer_re.md. This module is the
crypto kernel: it knows nothing about CAS / VTM / Hik-Connect; it just
encodes / decodes ECDH-wrapped opaque payloads.

Crypto primitives (matching the mbedTLS calls in the .so):

  - P-256 keypair          → cryptography.hazmat.primitives.asymmetric.ec
  - AES-256-ECB            → cryptography.hazmat.primitives.ciphers
  - ChaCha20 stream        → cryptography.hazmat.primitives.ciphers (ChaCha20)
  - HMAC-SHA256            → cryptography.hazmat.primitives.hmac
  - CRC32 (IEEE 802.3)     → zlib.crc32
  - ECDH (raw secret)      → ec.ECDH() exchange
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------- ECDH keypair management ----------

def generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    """Generate fresh P-256 keypair. Returns (priv_key_obj, pub_der91, priv_der_pkcs8).

    The 91-byte SubjectPublicKeyInfo DER goes on the wire at offset 43 of
    the ClientHello packet. The PKCS8 private key matches what
    mbedtls_pk_write_key_der emits — we keep it for the master-key
    derivation step but never put it on the wire.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_der = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert len(pub_der) == 91, f"unexpected DER pubkey length: {len(pub_der)}"
    return priv, pub_der, priv_der


# ---------- AES-256-ECB helpers ----------

def aes256_ecb_encrypt(key32: bytes, plaintext32: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes (got {len(key32)})")
    if len(plaintext32) % 16:
        raise ValueError("ECB plaintext must be multiple of 16 bytes")
    c = Cipher(algorithms.AES(key32), modes.ECB())
    e = c.encryptor()
    return e.update(plaintext32) + e.finalize()


def aes256_ecb_decrypt(key32: bytes, ciphertext: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes (got {len(key32)})")
    c = Cipher(algorithms.AES(key32), modes.ECB())
    d = c.decryptor()
    return d.update(ciphertext) + d.finalize()


# ---------- ChaCha20 stream ----------

def chacha20_encrypt(key32: bytes, nonce16: bytes, data: bytes) -> bytes:
    """cryptography's ChaCha20 takes a 16-byte 'nonce' = 4-byte counter (LE)
    + 12-byte standard nonce. This is the same layout the mbedtls
    chacha20_starts call expects (12-byte nonce + 4-byte initial counter)."""
    if len(key32) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce16) != 16:
        raise ValueError("cryptography.ChaCha20 needs 16-byte (counter+nonce)")
    c = Cipher(algorithms.ChaCha20(key32, nonce16), mode=None)
    return c.encryptor().update(data)


def chacha20_decrypt(key32: bytes, nonce16: bytes, data: bytes) -> bytes:
    return chacha20_encrypt(key32, nonce16, data)  # stream cipher → same op


# ---------- HMAC-SHA256 ----------

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


# ---------- ECDH shared secret ----------

def ecdh_shared_secret(priv: ec.EllipticCurvePrivateKey,
                      peer_pub_der91: bytes) -> bytes:
    """Returns the raw 32-byte ECDH shared secret (X coordinate of the
    shared point). Mirrors mbedtls_ecdh_calc_secret with 32-byte output."""
    peer_pub = serialization.load_der_public_key(peer_pub_der91)
    return priv.exchange(ec.ECDH(), peer_pub)


# ---------- ClientHello packet encoder ----------

@dataclass
class ClientHello:
    """Result of encode_ecdh_req_package() — keep all the bits that feed
    later steps (e.g., decrypting the server's reply)."""
    packet: bytes
    session_key32: bytes         # random session key (post-decrypt server can derive)
    client_priv: ec.EllipticCurvePrivateKey
    client_pub_der91: bytes
    nonce16: bytes


def encode_ecdh_req_package(
    *,
    kms_key32: bytes,            # arg3: device's KMS secretKey (32 bytes raw)
    plaintext: bytes,            # arg5: payload to encrypt (the first business message)
    flag: int = 0,               # arg2: 1-byte caller flag (offset 6 of header)
    session_key32: bytes | None = None,  # override for testing — usually random
    client_priv: ec.EllipticCurvePrivateKey | None = None,
    nonce16: bytes | None = None,
) -> ClientHello:
    """Build the ECDH ClientHello packet per docs/ecdh_layer_re.md.

    Returns a ClientHello dataclass; ClientHello.packet is the bytes to
    send. The other fields are needed to decrypt the server's reply.
    """
    if len(kms_key32) != 32:
        raise ValueError(f"KMS key must be 32 bytes (got {len(kms_key32)})")
    if session_key32 is None:
        session_key32 = os.urandom(32)
    if len(session_key32) != 32:
        raise ValueError("session_key32 must be 32 bytes")
    if client_priv is None:
        client_priv, client_pub_der91, _ = generate_p256_keypair()
    else:
        client_pub_der91 = client_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    if nonce16 is None:
        # Per disassembly: bytes [0..3] = LE counter starting at 1,
        # bytes [4..15] = the 12-byte nonce. The mbedtls_chacha20_starts call
        # passes nonce=sp+0xf4 (12 bytes). The .so seems to write
        # `str w27, [sp, #244]` with w27=1, then leave the rest zero —
        # so the 12-byte nonce is all zeros for the request packet.
        nonce16 = b"\x01\x00\x00\x00" + b"\x00" * 12

    data_len = len(plaintext)
    if data_len > 0x400:
        raise ValueError("plaintext too long (>1024 bytes per .so check)")

    # ----- Build 134-byte header -----
    hdr = bytearray(134)
    hdr[0] = 0x24
    hdr[1] = 0x01
    hdr[2] = 0x00
    struct.pack_into(">H", hdr, 3, data_len)
    hdr[5] = 0x01
    hdr[6] = flag & 0xFF
    # hdr[7..10] = 0x00 0x00 0x00 0x01 (LE u32 of 0x01000000 stored at offset 7)
    hdr[7:11] = b"\x00\x00\x00\x01"
    # hdr[11..42] = AES-256-ECB(session_key32, key=kms_key32) — two 16-byte blocks
    enc_session = aes256_ecb_encrypt(kms_key32, session_key32)
    hdr[11:43] = enc_session
    # hdr[43..133] = 91-byte DER pubkey
    hdr[43:134] = client_pub_der91

    # ----- ChaCha20-encrypt the payload -----
    enc_payload = chacha20_encrypt(session_key32, nonce16, plaintext)

    # ----- HMAC-SHA256 -----
    crc_hdr = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF
    crc_data = zlib.crc32(enc_payload) & 0xFFFFFFFF
    hmac_input = f"{crc_hdr}{crc_data}".encode("ascii")
    tag = hmac_sha256(kms_key32, hmac_input)
    assert len(tag) == 32

    packet = bytes(hdr) + enc_payload + tag
    return ClientHello(
        packet=packet,
        session_key32=session_key32,
        client_priv=client_priv,
        client_pub_der91=client_pub_der91,
        nonce16=nonce16,
    )


# ---------- Server reply decoder (preliminary) ----------

def decode_ecdh_req_package(
    *,
    kms_key32: bytes,
    packet: bytes,
) -> dict:
    """Decode an ECDH ClientHello from the wire (mirror of encode).
    Used to verify our encoder round-trips, and to parse server-side
    ECDH responses if they share the same envelope.

    Per the .so the matching function is
    ezviz_ecdh_decECDHReqPackage (924 bytes at 0x4bd0ec). Layout almost
    certainly mirrors the encoder; verifying HMAC first, then
    AES-decrypting the session key, then ChaCha20-decrypting the body.
    """
    if len(packet) < 134 + 32:
        raise ValueError("packet too small")

    # Verify HMAC
    tag = packet[-32:]
    body_with_hdr = packet[:-32]
    payload = body_with_hdr[134:]
    crc_hdr = zlib.crc32(body_with_hdr[:134]) & 0xFFFFFFFF
    crc_data = zlib.crc32(payload) & 0xFFFFFFFF
    expected_tag = hmac_sha256(kms_key32, f"{crc_hdr}{crc_data}".encode("ascii"))
    if expected_tag != tag:
        raise ValueError(f"HMAC mismatch (expected {expected_tag.hex()} got {tag.hex()})")

    # Parse header fields
    if packet[0] != 0x24:
        raise ValueError(f"bad packet tag 0x{packet[0]:02x}")
    declared_len = struct.unpack_from(">H", packet, 3)[0]
    if declared_len != len(payload):
        raise ValueError(
            f"length mismatch: header says {declared_len}, payload is {len(payload)}")
    flag = packet[6]

    enc_session = packet[11:43]
    session_key32 = aes256_ecb_decrypt(kms_key32, enc_session)

    peer_pub_der91 = packet[43:134]

    # Decrypt payload
    nonce16 = b"\x01\x00\x00\x00" + b"\x00" * 12
    plaintext = chacha20_decrypt(session_key32, nonce16, payload)

    return {
        "flag": flag,
        "session_key32": session_key32,
        "peer_pub_der91": peer_pub_der91,
        "plaintext": plaintext,
    }


# ---------- DataPackage (post-handshake encrypted message) ----------
#
# Reverse-engineered from
# EZVIZECDHCrypter::ezviz_ecdh_encECDHDataPackage @ 0x4bdf68:
#
#   offset  size  field
#   +0      1     0x24      (packet tag = 36 decimal — same as ReqPackage)
#   +1      1     0x02      (version = 2 — distinguishes from ReqPackage v=0x01)
#   +2      1     0x00
#   +3      2     BE uint16 of plaintext length
#   +5      2     0x00 0x00
#   +7      4     BE uint32 of sequence counter (incremented per packet, starts at 1)
#   +11     N     ChaCha20(plaintext,
#                          key   = session_key32 (the 32-byte session secret),
#                          nonce = 4-byte LE seq counter || 8 bytes 0x00)
#   +11+N   32    HMAC-SHA256("%u%u" % (crc32(packet[0..11]), crc32(ciphertext)),
#                              key = hmac_key32 (the ECDH master secret))
#
# Total length = N + 43.
#
# session_key32 is stored at ctx[7..38] by SetSessionEncKey, AES-decrypted
# from the ClientHello envelope. hmac_key32 is the post-handshake ECDH
# shared secret (raw `mbedtls_ecdh_calc_secret` output, 32 bytes).

def encode_ecdh_data_package(
    *,
    session_key32: bytes,    # 32-byte ChaCha20 key
    hmac_key32:    bytes,    # 32-byte HMAC-SHA256 key (master/shared secret)
    plaintext:     bytes,
    seq:           int = 1,
) -> bytes:
    if len(session_key32) != 32 or len(hmac_key32) != 32:
        raise ValueError("ECDH DataPackage keys must be 32 bytes each")
    if len(plaintext) > 0x400:
        raise ValueError("DataPackage plaintext capped at 1024 bytes by the .so")

    hdr = bytearray(11)
    hdr[0] = 0x24
    hdr[1] = 0x02
    hdr[2] = 0x00
    struct.pack_into(">H", hdr, 3, len(plaintext))
    hdr[5] = 0x00
    hdr[6] = 0x00
    struct.pack_into(">I", hdr, 7, seq)

    # ChaCha20 nonce: 4 bytes LE seq + 8 zero bytes (per disasm: `stur w8` at sp-84
    # for the first 4 bytes, then 8 bytes of zero from stur xzr at sp-80).
    # cryptography.ChaCha20 wants a 16-byte counter+nonce; we put the LE seq as the
    # counter portion (first 4 bytes) and the 12 zero bytes as the IV.
    nonce16 = struct.pack("<I", seq) + b"\x00" * 12
    enc = chacha20_encrypt(session_key32, nonce16, plaintext)

    crc_hdr  = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF
    crc_data = zlib.crc32(enc) & 0xFFFFFFFF
    tag = hmac_sha256(hmac_key32, f"{crc_hdr}{crc_data}".encode("ascii"))

    return bytes(hdr) + enc + tag


def decode_ecdh_data_package(
    *,
    session_key32: bytes,
    hmac_key32:    bytes,
    packet:        bytes,
) -> dict:
    if len(packet) < 11 + 32:
        raise ValueError("DataPackage too small")
    tag = packet[-32:]
    body_with_hdr = packet[:-32]
    enc = body_with_hdr[11:]
    crc_hdr  = zlib.crc32(body_with_hdr[:11]) & 0xFFFFFFFF
    crc_data = zlib.crc32(enc) & 0xFFFFFFFF
    expected = hmac_sha256(hmac_key32, f"{crc_hdr}{crc_data}".encode("ascii"))
    if expected != tag:
        raise ValueError(f"HMAC mismatch (exp {expected.hex()} got {tag.hex()})")
    if packet[0] != 0x24 or packet[1] != 0x02:
        raise ValueError(f"bad tag/version 0x{packet[0]:02x}/0x{packet[1]:02x}")
    seq = struct.unpack_from(">I", packet, 7)[0]
    declared_len = struct.unpack_from(">H", packet, 3)[0]
    if declared_len != len(enc):
        raise ValueError(f"length mismatch (header {declared_len} ≠ ct {len(enc)})")
    nonce16 = struct.pack("<I", seq) + b"\x00" * 12
    plaintext = chacha20_decrypt(session_key32, nonce16, enc)
    return {"seq": seq, "plaintext": plaintext}


# ---------- self-test ----------

def _selftest() -> None:
    """Encode + decode round-trip. KMS key fixed; everything else random."""
    kms = os.urandom(32)
    payload = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><Request><Cmd>Hello</Cmd></Request>"
    ch = encode_ecdh_req_package(kms_key32=kms, plaintext=payload, flag=0x05)
    decoded = decode_ecdh_req_package(kms_key32=kms, packet=ch.packet)
    assert decoded["session_key32"] == ch.session_key32
    assert decoded["peer_pub_der91"] == ch.client_pub_der91
    assert decoded["plaintext"] == payload
    assert decoded["flag"] == 0x05
    print(f"[hik_ecdh] req selftest OK ({len(ch.packet)} bytes, payload={len(payload)})")
    # DataPackage round-trip
    session_key = os.urandom(32)
    hmac_key = os.urandom(32)
    p = b"GET /Streaming/Channels/101"
    dp = encode_ecdh_data_package(session_key32=session_key, hmac_key32=hmac_key,
                                   plaintext=p, seq=42)
    out = decode_ecdh_data_package(session_key32=session_key, hmac_key32=hmac_key,
                                    packet=dp)
    assert out["seq"] == 42 and out["plaintext"] == p
    print(f"[hik_ecdh] data selftest OK ({len(dp)} bytes, payload={len(p)})")


if __name__ == "__main__":
    _selftest()
