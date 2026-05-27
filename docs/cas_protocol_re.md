# Hik-Connect CAS protocol — reverse-engineering notes

Source material: `libezstreamclient.so` (arm64-v8a, Hik-Connect 4.19,
extracted from the APK), the JNI binding declarations in
`com.hc.CASClient.*`, and live captures against `eucas.ezvizlife.com:6500`
through the partially-working `pyezvizapi.cas` implementation.

This document is the head-start for finishing the pure-Python port. We
have the message *bodies* but not the *envelope crypto layer* that the
real CAS enforces — see "Where it stops" at the bottom.

## End-to-end flow (what the Android app actually does)

```
1. REST: POST /v3/users/login/v2                 (works in Python today)
2. REST: GET  /v3/userdevices/v1/devices/pagelist   (works)
3. REST: GET  /v3/cameras/ticketInfo                (works — yields `ticket`)
4. REST: GET  /v3/streaming/vtm/{serial}/{ch}       (works — yields VTM addr + publicKey + KMS secretKey)
5. TLS:  connect eucas.ezvizlife.com:6500
6. ECDH: client hello → server ephemeral pubkey         ⚠ NOT YET RE'D
7. ECDH: shared secret → AES-128 session key            ⚠ NOT YET RE'D
8. CAS:  GetDevPermanentKey (encrypted msg type 0x?)    ⚠ blocked by 7
9. CAS:  InviteRealtimeStream (msg type 0x?)            body schema known, envelope NOT
10. CAS responds with VTM ticket + stream key
11. TCP: connect vtmcdsfra.ezvizlife.com:8554 (the VTM relay)
12. VTM: StreamInfoReq (protobuf, with hdSign over ECDH-derived bits)
13. VTM emits encrypted MPEG-PS frames over the open TCP socket
```

`pyezvizapi.cas.EzvizCAS.cas_get_encryption()` skips steps 6–7 and tries
step 8 in the clear. Older firmware accepted that; current EU CAS
silently drops the connection.

## CAS binary message envelope (32-byte header)

Confirmed on the wire by capturing `pyezvizapi.cas` traffic — even with
the silent-drop, our SEND went out and we saw it pre-TLS:

```
offset  size  field           value (for GetDevEncryption)
+0      4     magic           9e ba ac e9
+4      1     version         01
+5      6     reserved/flags  00 00 00 00 00 00
+11     1     msgType         02     (GetDevEncryption; see table below)
+12     6     reserved        00 00 00 00 00 00
+18     1     space           0x20 = ' '
+19     1     subType         01
+20     6     reserved        00 00 00 00 00 00
+26     2     bodyLen (BE)    02 09  = 521
+28     4     trailer         00 00 00 00
+32     N     body            <?xml … </Request>
+32+N   64    random hex      "0…f" (asciiz). Suspected HMAC slot.
```

The 64-byte trailing hex is the critical unknown. In `pyezvizapi.cas`
it's random (`random.randrange(10**80)`). For devices where CAS just
returns an empty response, this is almost certainly the failed
authentication tag — see "Where it stops" below.

### Known message types (`msgType` byte at offset 11)

| msgType | Name                          | Source                         |
|--------:|-------------------------------|--------------------------------|
| `0x02`  | GetDevEncryption              | `pyezvizapi.cas.cas_get_encryption` |
| `0x05`  | … (subtype 0x05)              | `pyezvizapi.cas.set_camera_defence` (first packet) |
| `0x13`  | … (defence ack/wrap)          | `pyezvizapi.cas.set_camera_defence` (second packet) |
| `0x14`  | SetCameraDefence              | `pyezvizapi.cas.set_camera_defence` (header) |
| `0x??`  | InviteRealtimeStream          | TODO — call CV3Protocol::ComposeMsgBody with the InviteRealtime body |
| `0x??`  | SetupRealtimeStream           | TODO — call CV3Protocol::ComposeMsgBody with the SetupRealtime body |
| `0x??`  | VerifyAndInviteStreamStart    | TODO — call CV3Protocol::ComposeMsgBody with the VerifyAndInvite body |

CV3Protocol::ComposeMsgBody is the encoder; it takes a `uint16_t`
message type as its first arg. The remaining codes are passed at call
sites that we'd need to find. The function is at vaddr `0x2a9bf4` size
8964 bytes in the arm64 .so — too big to crack here, would benefit from
ghidra + decompiler.

## XML message bodies — fully recovered

### `CreateInviteRealtimeStreamReq` (CChipParser::CreateInviteRealtimeStreamReq @ 0x2b2774)

```xml
<?xml version="1.0" encoding="utf-8" ?>
<Request>
    <OperationCode>{deviceOperationCode}</OperationCode>
    <Channel>{channelNo}</Channel>
    <RelatedDevice>{...optional…}</RelatedDevice>
    <ReceiverInfo>
        <Address>{clientIPOnNet}</Address>
        <Port>{clientPort}</Port>
        <ServerType>{0|1|...}</ServerType>
        <StreamType>MAIN | SUB | NewStreamType</StreamType>
        <TransProto>TCP | (UDP omitted-for-TCP-only-mode)</TransProto>
        <IsEncrypt>TRUE | FALSE</IsEncrypt>
    </ReceiverInfo>
    <ReceiverInfoEx>
        <SessionID>{sessionId}</SessionID>
        <Port>{altPort}</Port>
    </ReceiverInfoEx>
    <Authentication>
        <Ticket>{ticketInfo.ticket}</Ticket>
        <BizCode>{0 or business code}</BizCode>
    </Authentication>
    <Interval>{seconds}</Interval>
    <Uuid>{...}</Uuid>
    <Timestamp>{unix-ms}</Timestamp>
</Request>
```

`Ticket` is the value returned by `/v3/cameras/ticketInfo` — we already
have it cached under `logs/ticket.txt`. `OperationCode` is the
per-device operation code from `CASClient_GetDevOperationCode` (a
separate CAS call that takes session + serial and returns a short hex
string).

### `CreateSetupRealtimeStreamReq` (@ 0x2b3638)

```xml
<Request>
    <OperationCode>{...}</OperationCode>
    <Channel>{...}</Channel>
    <Identifier>{...}</Identifier>
    <ReceiverInfo>
        <NatAddress>{seenNATIP}</NatAddress>
        <NatPort>{seenNATPort}</NatPort>
        <UPnPAddress>{upnpIP}</UPnPAddress>
        <UPnPPort>{upnpPort}</UPnPPort>
        <InnerAddress>{lanIP}</InnerAddress>
        <InnerPort>{lanPort}</InnerPort>
        <StreamType>MAIN | SUB</StreamType>
        <IsEncrypt>TRUE | FALSE</IsEncrypt>
        <Udt>{0|1}</Udt>
        <Nat>{type-int}</Nat>
        <PortGuessType>{0|1|2}</PortGuessType>
        <Timeout>{ms}</Timeout>
    </ReceiverInfo>
</Request>
```

This is the P2P NAT-traversal setup; if we go the legacy P2P path we
need this. The VTM-relay path uses the Invite body and skips Setup.

### `CreateVerifyAndInviteStreamStartReq` (@ 0x2c02ec)

The simplest variant — combines "verify session" + "invite stream"
into one message. Likely the right call for a basic non-P2P stream.

```xml
<Request>
    <DevSerial>{C12345678}</DevSerial>
    <Url>{...optional, "NULL" if absent}</Url>
    <Type>{...}</Type>
    <Channel>{1..18}</Channel>
    <ReceiverInfo>
        <Address>{clientIP}</Address>
        <Port>{clientPort}</Port>
        <StreamType>MAIN | SUB</StreamType>
        <TransProto>TCP</TransProto>
        <IsEncrypt>TRUE | FALSE</IsEncrypt>
    </ReceiverInfo>
</Request>
```

### `CreateStartP2PReq` (@ 0x2c7004)

```xml
<Request>
    <OperationCode>{...}</OperationCode>
    <UPnP port="{...}" />
</Request>
```

## VTM streamurl format (what the C++ binary would send post-CAS)

From `StartStreamProcess` @ 0x325554 in libezstreamclient.so:

```
ysproto://<vtmHost>:<vtmPort>/live
    ?dev=<deviceSerial>
    &chn=<channel>
    &stream=<1=main,2=sub>
    &cln=<3 for android, 9 for ios>
    &isp=<isp-id, 0 default>
    &auth=<1 for ticket-bearer>
    &ssn=<vtdu_token_or_ticket>
    &weakstream=<int>     (optional)
    &isretry=<int>        (optional)
    &lid=<loginId>        (optional)
```

The modern variant adds `&hdSign=<sig>&busiProxy=1` where `hdSign` is
the SHA-256/HMAC-SHA256 of the URL params using the ECDH-derived AES
key as HMAC key — this is the part that nobody has reverse-engineered
publicly yet.

## VTM StreamInfoReq protobuf

Decoded from `_ZN3hik2ys14streamprotocol13StreamInfoReq21k*FieldNumberE`
constants in the .so:

```protobuf
message StreamInfoReq {
    optional string streamurl    = 1;   // the ysproto URL above
    optional string vtmstreamkey = 2;   // present on redirects (StreamInfoRsp.vtmstreamkey)
    optional string useragent    = 3;
    optional uint32 proxytype    = 4;
    optional string pdsstring    = 5;
    optional string clnversion   = 6;
}

message StreamInfoRsp {
    optional uint32 result        = 1;   // 0 = OK, 6001 = OPEN_PLAYFORM_VERIFY_DATA_ERROR
    optional bytes  datakey       = 2;   // AES key for the H.264 stream that follows
    optional bytes  streamhead    = 3;   // SPS/PPS / sysheader
    optional string streamssn     = 4;
    optional string vtmstreamkey  = 5;   // redirect target's key
    optional string serverinfo    = 6;
    optional string streamurl     = 7;   // redirect URL
    optional string srvinfo       = 8;
    optional bytes  aesmd5        = 9;   // MD5 of the datakey, for client verification
    optional bytes  udptransinfo  = 10;
    optional bytes  peerPBKey     = 11;  // device's public key
}

message StreamInfoNotify {
    optional string streamurl    = 1;
    optional string vtmstreamkey = 2;
    optional string useragent    = 3;
}
```

## Crypto primitives (from .so imports + strings)

The Hikvision libs import:

- `MD5_Init`, `MD5_Update`, `MD5_Final`              (OpenSSL libcrypto)
- `mbedtls_md_hmac_starts`, `_update`, `_finish`      (mbedTLS HMAC)
- AES128 (string constant — block size 16, mode TBD)
- ECDH on what looks like NIST P-256 (the VTM publicKey we extracted
  decoded as `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQg…` = standard
  ASN.1-DER P-256 public key)
- ECDHCryption_CreateSession → presumably ECDHE per-session
- `ECDHCryption_GenerateSessionKey` → KDF from shared secret

## Where it stops

Our `pyezvizapi.cas`-based capture sends a perfectly-shaped 32-byte
header + the XML body to `eucas.ezvizlife.com:6500`, and the server
either drops the connection or just doesn't respond for 8+ seconds.

The reason is the missing ECDH pre-handshake. The current CAS server
expects:

1. Open TLS connection (works for us)
2. **Client sends ECDH ClientHello** (a small binary message, msgType
   probably `0x01`, containing an ephemeral ECDSA P-256 pubkey)
3. **Server replies with its ephemeral pubkey + session ID**
4. Both derive AES-128 + IV from the shared secret + the device's KMS
   secretKey (which we already have cached in
   `logs/raw_devices.json:kmsInfos[serial].secretKey`)
5. **Now and only now** does GetDevEncryption / InviteRealtimeStream
   make sense — and the trailing 64-byte field is the HMAC tag over
   the body.

The exact byte format of the ECDH ClientHello, the KDF (HKDF-SHA256 is
the safe bet), and the HMAC scope are still unknown. They live inside
`ECDHCryption_CreateSession` and `ECDHCryption_GenerateSessionKey` in
the .so — both decently sized C++ functions that would need a few
focused hours in Ghidra to walk through.

Once that layer is reproduced in Python, the rest of the protocol is
ready to fire — XML schemas + message codes + VTM URL format + frame
protobufs are all here.

## Estimate to finish the pure-Python port

- ECDH handshake RE             ~4 h with Ghidra
- AES wrapper + HMAC tagging    ~1 h
- First CAS request that gets a response (GetDevOperationCode is the
                                simplest)   ~2 h
- InviteRealtimeStream working with a populated StreamInfoRsp ~3 h
- VTM hdSign computation (likely HMAC over query params)     ~2 h
- Frame decryption + Annex-B reframing                       ~2 h
- Plumbing + tests                                           ~2 h
- Total                          ≈ 1.5–2 dedicated days

…vs. a 30-second router config (Option A from the earlier email:
forward TCP 554 from the public-facing router to 192.168.0.101 on
the DVR's LAN), which gets you straight RTSP today, no protocol RE
needed at all.
