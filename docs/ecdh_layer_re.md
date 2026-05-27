# ECDH layer — wire format reverse-engineered

Source: `EZVIZECDHCrypter::ezviz_ecdh_encECDHReqPackage` @ 0x4bce14 in
libezstreamclient.so. Implementation uses **mbedTLS** primitives
(statically linked):

  - mbedtls_pk_init, mbedtls_pk_setup, mbedtls_pk_info_from_type(0x02
    = MBEDTLS_PK_ECKEY)
  - mbedtls_ecp_curve_info_from_grp_id(0x03 = MBEDTLS_ECP_DP_SECP256R1)
  - mbedtls_ecp_gen_key  → generates a fresh P-256 keypair per handshake
  - mbedtls_pk_write_pubkey_der / mbedtls_pk_write_key_der
  - mbedtls_aes_init / setkey_enc(256) / crypt_ecb
  - mbedtls_chacha20_init / setkey / starts / update
  - mbedtls_md_info_from_type(6 = MBEDTLS_MD_SHA256), HMAC

## ECDH ClientHello packet (`encECDHReqPackage` output)

```
offset  size  field
+0      1     0x24   (packet tag / version code = 36 decimal)
+1      1     0x01   (sub-version)
+2      1     0x00
+3      2     BE uint16 of plaintext-payload length
+5      1     0x01
+6      1     caller-supplied byte (call it `flag`)
+7      4     little-endian 0x01000000   (= bytes 00 00 00 01)
+11    32     AES-256-ECB(arg4, key=arg3)
              where arg3 = 32-byte device key (KMS secretKey)
              and arg4 = caller-supplied 32-byte session secret
+43    91     DER-encoded P-256 SubjectPublicKeyInfo
              (the client's fresh ephemeral public key)
+134    N     ChaCha20(plaintext, key=arg4,
                       nonce=12 bytes: first 4 = LE counter=1, rest=0
                       — possibly with some bytes from sp+0xf4+4 too)
+134+N  32    HMAC-SHA256(
                  text = sprintf("%u%u",
                                 crc32_ieee(bytes [0..134)),
                                 crc32_ieee(bytes [134..134+N))),
                  key  = arg3
              )
total: 166 + N bytes
```

## Function signature

C++:
```cpp
class EZVIZECDHCrypter {
    int ezviz_ecdh_encECDHReqPackage(
        void*    this_,            // x1 in C wrapper, x1 in method
        char     flag,             // x2 = the byte at packet[6]
        uint8_t* key32,            // x3 = HMAC + AES key (32 bytes)
        uint8_t* session32,        // x4 = AES-encrypted material + ChaCha20 key
        const char* plaintext,     // x5
        uint16_t plaintext_len,    // x6
        char*    out,              // x7 = output packet buffer
        uint32_t* out_len          // [stack] = result length
    );
};
```

`getInstance()` returns the singleton, ECDHCryption_EncECDHReqPackage()
is the C ABI wrapper.

## Key sources for the caller

| Input | Source |
|---|---|
| `key32`     | The device's KMS secretKey from `/v3/userdevices/v1/devices/pagelist`'s `kmsInfos[serial].secretKey` field. Returned as a 64-char hex string → 32 raw bytes. **WE ALREADY HAVE THIS** in `logs/raw_devices.json`. |
| `session32` | Per-handshake random 32-byte secret the client generates. Protected by AES-256-ECB(key=KMS) so only the server (which also knows the KMS key from its device DB) can recover it. |
| `flag`      | Caller-provided one-byte field; likely "client type" or "session role". `0x00` is the natural starting guess. |
| `plaintext` | The first business message of the session (probably the same XML body we already build in `scripts/hik_cas.py`). |
| Client P-256 keypair | Generated fresh per handshake via mbedTLS; we use `cryptography.hazmat.ec.generate_private_key(SECP256R1())` and serialize to DER `SubjectPublicKeyInfo`. |

## Inverse / response (`decECDHReqPackage`, `decECDHDataPackage`)

Both at addresses 0x4bd0ec (924 bytes) and 0x4bdc18 (528 bytes) in the
.so. TBD — same mbedTLS toolkit, mirror of encode. Implementation
strategy: write encode + symmetric decode in one pass, then verify
against real server bytes.

## Master key derivation

After the ClientHello + ServerHello exchange both sides hold an ECDH
shared secret. That gets fed into `ezviz_ecdh_GenerateMasterKey` /
`ezviz_ecdh_SrvGenerateMasterKey`. The KDF appears to be vanilla
SHA-256 or HKDF (mbedTLS HKDF is also in scope). The session AES/HMAC
keys for subsequent CAS messages are derived from this master.

## What's left

1. Disassemble `ezviz_ecdh_decECDHReqPackage` (the server-side decoder
   — tells us exactly what server expects).
2. Disassemble `ezviz_ecdh_GenerateMasterKey` (the post-handshake
   KDF).
3. Find the caller of `ezviz_ecdh_encECDHReqPackage` so we know what
   `flag` byte and what `plaintext` to populate for the first message.
4. Write the Python encoder using `cryptography.hazmat.primitives`:
   - `ec.generate_private_key(ec.SECP256R1())`
   - `Cipher(AES(key32), ECB())`  (mbedtls_aes_ecb compatible)
   - `ChaCha20Poly1305` — actually mbedtls_chacha20 is plain ChaCha20
     stream (no Poly1305); use `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`
   - `HMAC(key32, hashes.SHA256())`
   - `zlib.crc32` for the IEEE 802.3 CRC32.
5. Wire into `scripts/hik_cas.py`'s `cmd_invite` so the InviteRealtime
   request is ECDH-enveloped before sending.
6. Iterate against `eucas.ezvizlife.com:6500` until a non-empty
   response arrives.

Confidence rating: 80% of the encode side is reverse-engineered with
high certainty (the mbedTLS call shapes are exact). The 20% gap is
the flag byte and the exact ChaCha20 nonce layout — both knowable
from one read of the caller function and one read of the decode
function. Estimated 2–3 more focused turns to a working handshake.
