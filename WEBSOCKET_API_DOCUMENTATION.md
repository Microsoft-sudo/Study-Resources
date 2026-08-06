# Finvu Mobile WebSocket API Endpoints

**Base URLs:**
- **Production:** `wss://wsslive.finvu.in/api`
- **Development:** `wss://webvwdev.finvu.in/api`

---

## Message Structure

### Request
```json
{
  "header": {
    "mid": "uuid-v4",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id (null for pre-login APIs)",
    "dup": false,
    "type": "urn:finvu:in:app:req.<api>.01"
  },
  "payload": { ... }
}
```

### Response
```json
{
  "header": {
    "mid": "uuid-v4",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.<api>.01"
  },
  "payload": { ... }
}
```

> **`csid`** is an optional field in header, sent when applicable.

---

## Authentication & Account Management

### 1. Login — Username & Passcode

**Request:**
```json
{
  "header": {
    "mid": "dfe50c76-2da9-4c29-9ff2-6a1ef685981f",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.login.01"
  },
  "payload": {
    "username": "string",
    "password": "string",
    "deviceSecret": {
      "secret": "totp_string",
      "deviceId": "device_id"
    }
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "dfe50c76-2da9-4c29-9ff2-6a1ef685981f",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.login.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string",
    "deviceSimBindingValid": false
  }
}
```

> ⚠️ **VULNERABILITY — CRITICAL (confirmed): Authentication bypass / device-sim binding not enforced.**
> The server grants a fully-usable authenticated `sid` with **only** `username` + `password`. The `deviceSecret.secret` (rotating TOTP), `deviceId`, and the returned `deviceSimBindingValid` flag are **NOT validated**:
> - Real `deviceId` + **bogus** secret `"000000"` → `SUCCESS`, `sid` issued, `deviceSimBindingValid:false`.
> - **Fabricated** `deviceId` (`"deadbeef-device"`) + bogus secret → `SUCCESS`, `sid` issued.
> - `deviceSecret` omitted entirely → server does not reject on the device factor.
> - **Wrong password** → `FAILURE "Invalid username or password."` (password is the sole real gate).
> A `deviceSimBindingValid:false` session calls **all** post-login APIs successfully (`userInfo`, `userLinkedAccount` → 3 bank accounts, `getUserConsent` → 24 consents, `userConsentReport` → full CSV). See the **Security Testing & Vulnerability Findings** section at the end of this document.

---

### 2. Login — OTP Request

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.loginOtp.01"
  },
  "payload": {
    "username": "string (optional)",
    "mobileNum": "string (optional)",
    "handleId": "consent_handle_id"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.loginOtp.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "otpReference": "string",
    "message": "string"
  }
}
```

---

### 3. Login — OTP Verify

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.loginOtpVerify.01"
  },
  "payload": {
    "otp": "string",
    "otpReference": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.loginOtpVerify.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string",
    "sessionId": "string",
    "userId": "string"
  }
}
```

---

### 4. Device Binding

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.deviceSimBindingReg.01"
  },
  "payload": {
    "otpLessToken": "string",
    "deviceId": "string",
    "deviceSimInfo": {
      "osType": "string",
      "osVersion": "string",
      "appId": "string",
      "appVersion": "string",
      "simSerialNumber": "string"
    }
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.deviceSimBindingReg.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 5. Register

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.register.01"
  },
  "payload": {
    "username": "string",
    "mobileNumber": "string",
    "password": "string",
    "confirmPassword": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.register.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 6. Logout

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.logout.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.logout.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 7. Forgot Password — Initiate

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.forgotPassword.01"
  },
  "payload": {
    "userId": "string",
    "mobileNumber": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.forgotPassword.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 8. Forgot Password — Verify OTP

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.forgotPasswordVerify.01"
  },
  "payload": {
    "userId": "string",
    "mobileNumber": "string",
    "otp": "string",
    "newPassword": "string",
    "confirmPassword": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.forgotPasswordVerify.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 9. Forgot Handle — Initiate

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.forgotHandle.01"
  },
  "payload": {
    "mobileNumber": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.forgotHandle.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "otpReference": "string",
    "message": "string"
  }
}
```

---

### 10. Forgot Handle — Verify OTP

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:req.forgotHandleVerify.01"
  },
  "payload": {
    "otp": "string",
    "otpReference": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": null,
    "dup": false,
    "type": "urn:finvu:in:app:res.forgotHandleVerify.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "userIds": ["string"],
    "message": "string"
  }
}
```

---

### 11. Change Passcode

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.chpassword.01"
  },
  "payload": {
    "username": "string",
    "currentPassword": "string",
    "newPassword": "string",
    "confirmPassword": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.chpassword.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 12. Close Finvu Account

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.userAccountUnregister.01"
  },
  "payload": {
    "password": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.userAccountUnregister.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 13. Mobile Verification — Initiate

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.mobileVerification.01"
  },
  "payload": {
    "mobileNumber": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.mobileVerification.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 14. Mobile Verification — Verify OTP

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.mobileVerificationVerify.01"
  },
  "payload": {
    "mobileNumber": "string",
    "otp": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.mobileVerificationVerify.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string",
    "verified": true
  }
}
```

---

## User Information

### 15. User Info

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.userInfo.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.userInfo.01"
  },
  "payload": {
    "userId": "string",
    "mobileNumber": "string",
    "email": "string",
    "createdAt": "string",
    "updatedAt": "string"
  }
}
```

---

### 16. Entity Info

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.entityInfo.01"
  },
  "payload": {
    "entityId": "string",
    "entityType": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.entityInfo.01"
  },
  "payload": {
    "entityId": "string",
    "entityType": "string",
    "entityName": "string",
    "entityDetails": {}
  }
}
```

---

## FIP Management

### 17. FIPs All

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id (optional)",
    "dup": false,
    "type": "urn:finvu:in:app:req.fipsAll.01"
  },
  "payload": {}
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.fipsAll.01"
  },
  "payload": {
    "fips": [
      {
        "fipId": "string",
        "fipName": "string",
        "fipLogoUrl": "string",
        "fiTypes": ["string"]
      }
    ]
  }
}
```

---

### 18. FIP Details

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.fipDetails.01"
  },
  "payload": {
    "fipId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.fipDetails.01"
  },
  "payload": {
    "fipId": "string",
    "fipName": "string",
    "fipLogoUrl": "string",
    "fiTypes": ["string"],
    "identifierTypes": ["string"]
  }
}
```

---

## Account Discovery & Linking

### 19. Account Discover

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.discover.01"
  },
  "payload": {
    "Customer": {
      "Identifiers": [
        {
          "category": "string",
          "type": "string",
          "value": "string"
        }
      ],
      "id": "string"
    },
    "FIPDetails": {
      "fipId": "string",
      "fipName": "string"
    },
    "FITypes": ["string"],
    "timestamp": "2024-05-15T06:58:09.877Z",
    "txnid": "uuid",
    "ver": "2.0.0"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.discover.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "discoveredAccounts": [
      {
        "accType": "string",
        "accRefNumber": "string",
        "maskedAccNumber": "string",
        "FIType": "string"
      }
    ],
    "message": "string"
  }
}
```

---

### 20. Account Discover Async

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.discoverAsync.01"
  },
  "payload": {
    "Customer": {
      "Identifiers": [
        {
          "category": "string",
          "type": "string",
          "value": "string"
        }
      ],
      "id": "string"
    },
    "FIPDetails": {
      "fipId": "string",
      "fipName": "string"
    },
    "FITypes": ["string"],
    "timestamp": "2024-05-15T06:58:09.877Z",
    "txnid": "uuid",
    "ver": "2.0.0"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.discoverAsync.01"
  },
  "payload": {
    "status": "PENDING | SUCCESS | FAILURE",
    "requestId": "string",
    "message": "string"
  }
}
```

---

### 21. Account Linking

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.linking.01"
  },
  "payload": {
    "Customer": {
      "Accounts": [
        {
          "accRefNumber": "string",
          "accType": "string",
          "FIType": "string"
        }
      ],
      "id": "string"
    },
    "FIPDetails": {
      "fipId": "string",
      "fipName": "string"
    },
    "timestamp": "2024-05-15T06:58:09.877Z",
    "txnid": "uuid",
    "ver": "2.0.0"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.linking.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "RefNumber": "string",
    "authenticators": [
      {
        "type": "string",
        "value": "string"
      }
    ],
    "message": "string"
  }
}
```

---

### 22. Account Linking Confirm

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.confirm-token.01"
  },
  "payload": {
    "accountLinkingRefNumber": "string",
    "timestamp": "2024-05-15T06:58:09.877Z",
    "token": "string",
    "txnid": "uuid",
    "ver": "2.0.0"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.confirm-token.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "Accounts": [
      {
        "linkRefNumber": "string",
        "accRefNumber": "string",
        "maskedAccNumber": "string",
        "accType": "string",
        "FIType": "string",
        "status": "string"
      }
    ],
    "message": "string"
  }
}
```

---

### 23. Linked Accounts

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.userLinkedAccount.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.userLinkedAccount.01"
  },
  "payload": {
    "linkedAccounts": [
      {
        "linkRefNumber": "string",
        "accRefNumber": "string",
        "maskedAccNumber": "string",
        "accType": "string",
        "FIType": "string",
        "fipId": "string",
        "fipName": "string",
        "status": "string"
      }
    ]
  }
}
```

---

### 24. Unlink Account

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.unlinking.01"
  },
  "payload": {
    "ver": "2.0.0",
    "timestamp": "2024-05-15T06:58:09.877Z",
    "txnid": "uuid",
    "linkedAccountReference": {
      "customerAddress": "string",
      "linkReferenceNumber": "string",
      "accountReferenceNumber": "string"
    },
    "fipReferenceView": {
      "fipId": "string",
      "fipName": "string"
    }
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.unlinking.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

## Consent Management

### 25. Request Account Consent (Self Consent)

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountConsentRequest.01"
  },
  "payload": {
    "ver": "2.0.0",
    "txnid": "uuid",
    "consentHandleId": "",
    "handleStatus": null,
    "createTime": "2024-05-15T06:58:09.877Z",
    "startTime": "2024-05-15T06:58:09.877Z",
    "expireTime": "2025-05-15T06:58:09.877Z",
    "statusLastupdateTimestamp": "2024-05-15T06:58:09.877Z",
    "consent": "Y",
    "consentDetailDigitalSignature": "",
    "Signature": "AA signature",
    "mode": "STORE",
    "fetchType": "ONETIME",
    "consentTypes": ["PROFILE", "SUMMARY", "TRANSACTIONS"],
    "fiTypes": ["DEPOSIT"],
    "Frequency": {
      "unit": "MONTH",
      "value": 1
    },
    "DataLife": {
      "unit": "YEAR",
      "value": 1
    },
    "DataDateTimeRange": {
      "from": "2024-01-01T00:00:00.000Z",
      "to": "2024-05-15T06:58:09.877Z"
    },
    "Purpose": {
      "code": "101",
      "refUri": "https://api.rebit.org.in/aa/purpose/101.xml",
      "text": "string",
      "Category": {
        "type": "Personal Finance"
      }
    },
    "AA": {
      "id": "string"
    },
    "FIU": null,
    "User": {
      "idTypes": "USER",
      "id": "string"
    },
    "FIPDetails": [
      {
        "fip": {
          "id": "string",
          "name": null
        },
        "accounts": [
          {
            "fiType": "string",
            "fipId": "string",
            "accountType": "string",
            "accountReferenceNumber": "string",
            "maskedAccountNumber": "string",
            "linkReferenceNumber": "string",
            "fipName": "string"
          }
        ]
      }
    ],
    "ConsentUse": {
      "logUri": "consent_use_loguri",
      "count": 1,
      "lastUseDateTime": "2024-05-15T06:58:09.877Z"
    },
    "DataFilter": null
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountConsentRequest.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "consentDetail": {
      "consentHandleId": "string",
      "consentId": "string",
      "consentStatus": "string"
    },
    "message": "string"
  }
}
```

---

### 26. Fetch Consent Request Details

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.consentRequestDetails.01"
  },
  "payload": {
    "userId": "string",
    "consentHandleId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.consentRequestDetailsResponse.01"
  },
  "payload": {
    "consentDetail": {
      "consentHandleId": "string",
      "consentId": "string",
      "createTime": "string",
      "expireTime": "string",
      "fiuId": "string",
      "fiuName": "string",
      "purpose": {},
      "accounts": [],
      "consentStatus": "string"
    }
  }
}
```

---

### 27. Fetch Consent Details

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.getConsentDetails.01"
  },
  "payload": {
    "userId": "string",
    "consentId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.getConsentDetails.01"
  },
  "payload": {
    "consentDetail": {
      "consentId": "string",
      "createTime": "string",
      "expireTime": "string",
      "consentStatus": "string",
      "accounts": [],
      "fiTypes": [],
      "mode": "string",
      "fetchType": "string"
    }
  }
}
```

---

### 28. Process Consent Request — Approve

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountConsentRequest.01"
  },
  "payload": {
    "consentHandleId": "string",
    "handleStatus": "ACCEPT",
    "fiu": {
      "id": "string"
    },
    "fipDetails": [
      {
        "fip": { "id": "string" },
        "accounts": []
      }
    ]
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountConsentRequest.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 29. Process Consent Request — Deny

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountConsentRequest.01"
  },
  "payload": {
    "consentHandleId": "string",
    "handleStatus": "DENY",
    "fiu": {
      "id": "string"
    },
    "fipDetails": null
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountConsentRequest.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 30. Get User Consents

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.getUserConsent.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.getUserConsent.01"
  },
  "payload": {
    "consents": [
      {
        "consentId": "string",
        "consentIntentId": "string",
        "consentStatus": "string",
        "createTime": "string",
        "expireTime": "string",
        "fiuId": "string",
        "consentMode": "string"
      }
    ]
  }
}
```

---

### 31. Revoke Consent

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.consent-revoke.01"
  },
  "payload": {
    "userId": "string",
    "consentId": "string",
    "revokeType": "REVOKED",
    "accountAggregator": {
      "id": "string"
    },
    "fipDetails": {
      "fipId": "string",
      "fipName": "string"
    }
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.consent-revoke.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "message": "string"
  }
}
```

---

### 32. Consent Handle Status

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.consentHandleStatus.01"
  },
  "payload": {
    "handleId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.consentHandleStatus.01"
  },
  "payload": {
    "handleId": "string",
    "status": "string",
    "message": "string"
  }
}
```

---

### 33. Consent History

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.consentHistory.01"
  },
  "payload": {
    "consentId": "string",
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.consentHistory.01"
  },
  "payload": {
    "consentId": "string",
    "history": [
      {
        "timestamp": "string",
        "status": "string",
        "action": "string"
      }
    ]
  }
}
```

---

### 34. User Consent Report

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.userConsentReport.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.userConsentReport.01"
  },
  "payload": {
    "totalConsents": 0,
    "activeConsents": 0,
    "expiredConsents": 0,
    "revokedConsents": 0,
    "consents": []
  }
}
```

---

## Data Fetch

### 35. Account Data Request

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountDataRequest.01"
  },
  "payload": {
    "ver": "2.0.0",
    "timestamp": "2024-05-15T06:58:09.877Z",
    "txnid": "uuid",
    "fiDataRange": {
      "from": 1704067200000,
      "to": 1715760000000
    },
    "consent": {
      "id": "consent_id",
      "digitalSignature": ""
    },
    "keyMaterial": {
      "cryptoAlg": "ECDH",
      "curve": "Curve25519",
      "params": "string",
      "DHPublicKey": {
        "expiry": "2024-06-15T06:58:09.877Z",
        "Parameters": "",
        "KeyValue": "PEM_encoded_public_key"
      },
      "Nonce": "string"
    }
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountDataRequest.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "sessionId": "string",
    "message": "string"
  }
}
```

---

### 36. Account Data Fetch

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.accountData.01"
  },
  "payload": {
    "SessionID": "string",
    "ConsentID": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.accountData.01"
  },
  "payload": {
    "status": "SUCCESS | FAILURE",
    "fiData": [
      {
        "fipId": "string",
        "data": [
          {
            "linkRefNumber": "string",
            "maskedAccNumber": "string",
            "encryptedFI": "string"
          }
        ]
      }
    ],
    "message": "string"
  }
}
```

---

## Offline Messages

### 37. Fetch Offline Messages

**Request:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:09.877Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:req.userOfflineMessages.01"
  },
  "payload": {
    "userId": "string"
  }
}
```

**Response:**
```json
{
  "header": {
    "mid": "uuid",
    "ts": "2024-05-15T06:58:10.123Z",
    "sid": "session_id",
    "dup": false,
    "type": "urn:finvu:in:app:res.userOfflineMessages.01"
  },
  "payload": {
    "offlineMessages": [
      {
        "messageId": "string",
        "messageType": "CONSENT_REQUESTED",
        "requestConsentId": "string",
        "timestamp": "string",
        "data": {}
      }
    ]
  }
}
```

---

## Notes

- **`sid`** is `null` for pre-login APIs (register, login, forgot password/handle). All post-login APIs require a valid session ID.
- **`mid`** is a UUID v4 generated per request.
- **`ts`** is ISO 8601 format: `2024-05-15T06:58:09.877Z`.
- **`dup`** is `false` for new requests; `true` for retries.
- **`csid`** is an optional field present in some requests.
- **`ver`** in payload is `"2.0.0"` (ReBIT version).
- **`txnid`** in payload is a UUID v4.

---

## Security Testing & Vulnerability Findings

**Scope:** Authorized VAPT of the FinVu dev/VAPT build (`com.finvu.development` 2.2.2-dev) against the dev backend `wss://webvwdev.finvu.in/apiv2`. Testing was performed with a custom Python WebSocket harness (`finvu_ws_test.py` / `finvu_coverage.py`) implementing the `mid`-correlated request/response protocol; sessions were harvested via `adb logcat` (`FinvuNetworkingManager` tag) on a rooted OnePlus 6T. All credentials are the pentester's own dev test account. No Frida/instrumentation was used; all testing was manual black-box against the WS API surface.

**Coverage:** All 37 documented endpoints were exercised. Auth-related flows that require a live Otpless/OTP handoff (`loginOtp`, `loginOtpVerify`, `mobileVerification*`, `forgotPassword`, `forgotHandle`, `register`) were probed for error handling but not driven to completion, as they need a live OTP delivery.

### Finding 1 — Authentication bypass: device-sim binding / TOTP second factor not enforced
**Severity: CRITICAL** | **API:** `urn:finvu:in:app:req.login.01` | **Confirmed: YES**

The login endpoint presents a `deviceSecret` object (`{deviceId, secret}`) as a TOTP-based device-sim binding second factor, but the server does **not** validate it. Only `username` + `password` are authenticated.

| Case | deviceId | deviceSecret.secret | password | Result |
|------|----------|--------------------|----------|--------|
| A | real (`392368b0-…`) | **bogus** `"000000"` | correct `1436` | **SUCCESS**, `sid` issued, `deviceSimBindingValid:false` |
| B | **fabricated** `"deadbeef-device"` | bogus `"000000"` | correct | **SUCCESS**, `sid` issued, `deviceSimBindingValid:false` |
| C | — | **omitted** | correct | not rejected on the device factor |
| D (control) | real | bogus | **wrong** | `FAILURE "Invalid username or password."` |

A session obtained with a **bogus** `deviceSecret`/`deviceId` (`deviceSimBindingValid:false`) successfully calls the full post-login catalog:

| Post-login API | Result with bypass `sid` |
|----------------|--------------------------|
| `userInfo` | **ACCEPT** — full profile returned |
| `userLinkedAccount` | **SUCCESS** — 3 linked bank accounts |
| `getUserConsent` | **SUCCESS** — 24 consents |
| `userConsentReport` | **SUCCESS** — full consent CSV report |
| `getConsentDetails` / `fipDetails` / `entityInfo` | **SUCCESS** |

**Impact:** The entire device-sim binding / TOTP second factor is decorative. An attacker who obtains only a victim's handle + passcode gets a fully functional session that discloses the victim's profile, all linked financial accounts, all consents and consent history/report, and can drive consent/data-fetch flows. This defeats the multi-factor authentication design.

**Reproduce:** `python3 finvu_auth_decisive.py` (Case A/B) and `python3 finvu_coverage.py` (login uses `deviceSecret="000000"`, then full coverage).
**Fix:** Server-side validate `deviceSecret.secret` against the TOTP derived from the registered `deviceId`'s seed; reject logins where `deviceSimBindingValid` would be `false` (or gate post-login APIs on it). Bind the issued `sid` to the verified `deviceId` and reject mismatches.

### Finding 2 — Weak sole authentication factor: 4-digit numeric passcode with no brute-force lockout
**Severity: HIGH** | **API:** `req.login.01` | **Confirmed: YES**

The account's passcode is a 4-digit numeric value (`1436`). Combined with Finding 1 (deviceSecret not checked), the passcode is the **only** credential. A controlled probe of 5 consecutive wrong-password logins (correct handle, wrong passcode, ~3s apart) all returned identical `FAILURE "Invalid username or password."` with **no account lockout, no increasing delay, no CAPTCHA, and no rate limit**. The only `RETRY` observed was the unrelated one-session-per-user session lock ("User … already logged in"), not a password-throttling control.

| Attempt | Status | Message |
|---------|--------|---------|
| 1 | RETRY | User 7666213741@finvu already logged in. Please retry. *(session lock, not password lock)* |
| 2–6 | FAILURE | Invalid username or password. *(no throttling)* |

**Impact:** The handle is `<mobile_number>@finvu` (mobile numbers are semi-public), so an attacker knowing only a target's mobile number can brute-force the 4-digit passcode (10 000 keyspace) against `login.01` with a fabricated `deviceId`/`deviceSecret` and, on success, take over the account per Finding 1. At the observed unthrottled rate this is feasible in minutes to low hours.
**Reproduce:** `python3 finvu_lockout_probe.py`.
**Fix:** Enforce a minimum passcode strength (≥8 chars, mixed), add per-account/per-IP brute-force lockout with exponential backoff, and require the validated device factor (Finding 1 fix) so the passcode is not the sole factor.

### Finding 3 — Financial metadata disclosure to unbound session (consent report)
**Severity: MEDIUM** | **APIs:** `req.userConsentReport.01`, `req.getUserConsent.01`, `req.userLinkedAccount.01` | **Confirmed: YES**

`userConsentReport` returns a Base64-encoded CSV (`ConsentId,Status,CreatedOn,StatusUpdatedOn,…`) covering every consent for the account, and `getUserConsent`/`userLinkedAccount` return the full consent list (24) and all linked bank accounts (3). All of this is returned to a `deviceSimBindingValid:false` session (Finding 1). Even with the auth bypass fixed, the volume of financial-account and consent metadata returned to a legitimately logged-in client is broad; ensure these responses are scoped to the minimum necessary and that revocation/audit covers report generation.
**Fix:** Confirm report/list endpoints require the fully validated session (post Finding 1 fix) and log/alert on report generation; consider masking account references in list views.

### Finding 4 — One-session-per-user enables session DoS / forced logout
**Severity: LOW** | **API:** `req.login.01` (session lifecycle) | **Confirmed: YES**

Each successful `SUCCESS` login for a user invalidates that user's prior `sid`s (one active session per user). Any party who can authenticate the account (via Finding 1/2) can repeatedly log in and force-terminate the victim's active app session, causing a denial-of-service / repeated disconnect of the legitimate user. The session-replacement also surfaces a weak activity oracle: a login attempt for a user with an active session can return `RETRY "… already logged in"`, revealing that the target currently has a live session.
**Fix:** Allow concurrent device-bound sessions (bound to the verified `deviceId`), or require the validated device factor before invalidating an existing session; suppress the "already logged in" oracle for unauthenticated callers.

### Positive controls confirmed (defenses present)
These were tested and found to be correctly enforced — included so they are not re-reported as issues:

- **Session enforcement on post-login APIs:** `userInfo` with `sid=null` → rejected; `userInfo` with a bogus `sid` → `Session Error`. The bypass is at **login**, not at the API authorization layer — once a (bogus-factor) `sid` is issued, it is honored.
- **No IDOR across users:** `getUserConsent`, `userLinkedAccount`, `getConsentDetails` invoked with another user's `userId` (`7666213742@finvu`) and the caller's own `sid` returned **no** other-user data (`status=FAILURE`, 0 consents/accounts). Resources are scoped to the `sid` owner.
- **Logout acts on `sid`, not supplied `userId`:** `logout` with `userId=other` and the caller's `sid` terminated the caller's own session (no logout-IDOR).
- **Destructive action re-verifies password:** `userAccountUnregister` with a wrong password → `FAILURE "Invalid username/password. Authentication failed."`
- **Input validation present:** malformed `accountConsentRequest` → `Bad Request`; `discover`/`discoverAsync` without a strong identifier → `"At least one strong identifier required for discovery."`; malformed `confirm-token` / `unlinking` / `accountDataRequest` → `"Error parsing payload."`; malicious/SQL-ish `userId` → rejected.
- **No user enumeration via error messaging on pre-login flows:** `register` (existing handle), `forgotPassword`/`forgotHandle` (nonexistent mobile) did not return differentiated errors (the server did not surface user-existence information).

### Test artifacts
- `finvu_ws_test.py` — main harness (WS client, 37 API wrappers, security suite, REPL).
- `finvu_auth_decisive.py` — decisive 4-case login bypass proof (Finding 1).
- `finvu_coverage.py` — clean single-login 37-API coverage (proves bypass session reaches all post-login data).
- `finvu_lockout_probe.py` — wrong-password throttling probe (Finding 2).
- `finvu_test_config.json` — endpoint + pentester test-account creds (dev backend only; do not commit).
