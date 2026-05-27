# VTM redirect-hop — code map (libezstreamclient.so disassembly)

## What works (confirmed live)

1. **REST chain** — login → device list → ticketInfo → streaming/vtm/{serial}/{ch}
2. **NEW**: `POST /api/user/token/get` (form fields `featureCode`, `count`) returns
   `{"tokenArray": [...]}`. The SDK passes this array to `NativeApi.setTokens`
   (`EZStreamClientManager.java:319`). Confirmed live, got 10 tokens of form `ut.XXX`.
3. **VTM step 1**: send `STREAMINFO_REQ` (mcode `0x13B`) on channel `MESSAGE (0)`:
   - field 1 streamurl = `ysproto://<vtm-host>:<vtm-port>/live?dev=&chn=&stream=&cln=3&isp=0&auth=1&ssn=<token>&lid=<user>&hdSign=<sig>`
   - field 3 useragent / field 6 clnversion = `v3.6.3.20221124`
   - field 4 proxytype = `0`
   - field 5 pdsstring = base64(DER P-256 pubkey)
   - hdSign = `HMAC-SHA256(secretKey[:32].utf8, url_base).hex()`
   - Returns `result=5302` + new streamurl + vtmstreamkey

## Code map of the 5302 handler

**`ProcessServerInfoRsp` @ 0x33c518** detects `result==5302` at line 33c7c4
(`mov w8, #0x14b6` then `cmp; b.eq 33d784`). The branch at **0x33d784** does:

```
33d7d0  bl Encrypt::cancel_handshake  // sets Encrypt[56] = 0 (reset bit)
33d7dc–33d854  Build std::string at sp+0x1588 from parsed_resp+0x8  // = streamurl
33dff0  copy that string into a local
33e008  bl SetProxySrvInfo(this, &local_url, &out)
33e030  cbz w8  → if SetProxySrvInfo succeeded, branch to 33e208 (continue)
                  else fall through to write at 33e0f0:
33e0f0  CStreamCln + 0xad28 ← (one of multiple URL-derived strings)
33e2ec  CStreamCln + 0xad28 ← another write in yet another branch
```

So **CStreamCln + 0xad28** (the pdsstring source for the NEXT `STREAMINFO_REQ`)
is set to a URL string derived from the redirect response. Specifically the
first write copies `parsed_resp + 0x8` which `ParseServerInfoRsp` maps to
**field 7 = `streamurl`** (proven by line 37b65c calling
`StreamInfoRsp::streamurl()` and storing at struct offset `0x8`).

**`CreateMessage` @ 0x338304** reads `this+0xad28` and copies it into
`INFO_S+0x10`, which `CreateMsgBody` puts into the protobuf as field 5
(`set_pdsstring` @ 37a4c0).

So per the code, **step 2's `pdsstring` should be the redirect URL itself**,
not `base64(DER pubkey)`.

## What the test says

Tested step 2 with `pdsstring = info1.streamurl` (the verbatim redirect URL):
**result=6001** (same as base64(DER) — the recognized but failing case).
Tested `pdsstring=""` and absent → `6110` (missing field).

So the server does accept the pdsstring shape we send (whether DER-b64 or
URL-string), but the auth still fails with `verify_data error (6001)`.

## Other things mapped (this session)

- **`EZClientManager::getToken(out, max, &size)` @ 0x234d74** is a token QUEUE:
  pops `tokens[head]`, increments head, decrements count. 11 callers across the
  SDK. Pre-filled via `setTokens(String[])` from the Java side.
- **`ConnectServerAndSendMsg(uint32_t arg)` @ 0x351fa8** is the connect+send
  primitive. Three callers pass arg = 0, 1, 2:
  - StreamThreadFunc (arg=0) — initial connect
  - ProcessNornmalMsg (arg=1, arg=2) — different state-handler branches
  - Internally maps arg=2 → CreateMessage's third param = 1, which makes
    `ModifyOriginalUrl` SKIP the URL modification.
  - arg=0 or 1 → CreateMessage param = 0 → `ModifyOriginalUrl` runs.
- **`ModifyOriginalUrl` @ 0x33b4fc** does `URL.replace("ssn=", this+0x2928)`
  when run. `this+0x2928` is filled by `CopyInputParas` from
  `input_struct+0x511` (which is filled by `startPreview` from `getToken`'s
  output — so it's the NEXT pre-fetched token from the queue).
- **`Encrypt::enc` @ 0x36593c** wraps the serialized protobuf in either
  `EncECDHReqPackage` (handshake) or `EncECDHDataPackage` (post-handshake)
  based on `[Encrypt+56] bit 0`. Triggered by `CreateMessage` when
  `[this+10492] == 2`, which also changes the outgoing channel to `0x0A`
  (ENCRYPTED_MESSAGE).

## What's still unknown

The server's `6001` ("VERIFY_DATA_ERROR") fires after our request has passed
shape checks. Code-readable inputs to step 2's protobuf are all 6 fields, and
none of the combinations we can produce client-side change `6001` → success.

This means the server is comparing something it knows about us (from step 1's
state) against something derived from step 2's request that **isn't a plain
protobuf field value**. Candidates we cannot disambiguate from the SDK
alone:

1. A per-TCP-connection MAC bound to the source IP+port pair.
2. An ECDH-derived session secret that the server expects us to have proven
   knowledge of (e.g., a Diffie-Hellman secret hash). Our pdsstring carries
   our ephemeral pubkey, and the cluster shares device-side state, so the
   server CAN derive the shared secret on its end — we are not visibly
   proving knowledge of it on step 2.
3. A "sequence" or "anti-replay" counter from the VTM packet header that
   has to be a specific value on step 2 (we currently send `sequence=0`).

Without a wire capture from the real Android app, we cannot tell which.
The remaining feasible work that does not require an Android device:

- Try sequence values != 0 in the VTM packet header on step 2.
- Try to prove knowledge of the ECDH secret by computing
  `HMAC(ECDH_shared, vtmstreamkey || redirect_url)` and stashing it in a
  field we haven't yet weaponized (the protobuf string is utf-8; we cannot
  add a 7th field). Possibly URL-encoded as an extra query parameter.

## URL parameter templates in .rodata (just for reference)

```
dev=                    @ 0x148972
&chn=                   @ 0x15250c
&stream=                @ 0x171cd8
&cln=                   @ 0x17106b
&isp=                   @ 0x155c81
&auth=                  @ 0x159798
&ssn=                   @ 0x146ca1  (and "ssn=" @ 0x14becc — used by ModifyOriginalUrl)
&lid=                   @ 0x1577ee
hdSign=%s               @ 0x161a24
hdSign=%s&busiProxy=1   @ 0x154f33  (busiProxy mode)
hdSign=%s&playback=%d   @ 0x15d993  (playback)
&mode=1&authtype=1&authssn= @ 0x161966  (TALKBACK URLs in EZStreamClientProxy::getNewTTSUrl — not preview)
```

No "extra param" we're missing in preview URLs.
