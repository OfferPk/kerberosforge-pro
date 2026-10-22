/**
 * KerberosForge Pro - Protocol Engine (IETF RFC 4120)
 * Implements Kerberos V5 ASN.1 DER Wireframe Encoding, Message Dissection,
 * Pre-Authentication Modeling, and Kerberoasting Risk Analysis.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.KerberosProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- RFC 4120 Constants ---
  var CONSTANTS = {
    PORT: 88,
    PROTOCOL_VERSION: 5,

    // Message Types (RFC 4120 Section 5.3 & 5.4)
    MSG_AS_REQ: 10,
    MSG_AS_REP: 11,
    MSG_TGS_REQ: 12,
    MSG_TGS_REP: 13,
    MSG_AP_REQ: 14,
    MSG_AP_REP: 15,
    MSG_KRB_SAFE: 20,
    MSG_KRB_PRIV: 21,
    MSG_KRB_CRED: 22,
    MSG_KRB_ERROR: 30,

    // Pre-Authentication Types (RFC 4120 Section 5.2.7)
    PA_TGS_REQ: 1,
    PA_ENC_TIMESTAMP: 2,
    PA_PW_SALT: 3,
    PA_ETYPE_INFO: 11,
    PA_PK_AS_REQ: 16,        // RFC 4556 PKINIT
    PA_ETYPE_INFO2: 19,
    PA_PAC_REQUEST: 128,     // Microsoft PAC Request
    PA_FOR_USER: 129,        // S4U2Self
    PA_FX_COOKIE: 133,
    PA_ENCRYPTED_CHALLENGE: 138, // RFC 6113 FAST

    // Encryption Types (RFC 3961, 3962, 4120, 8009)
    ETYPE_DES_CBC_CRC: 1,
    ETYPE_DES_CBC_MD5: 3,
    ETYPE_DES3_CBC_SHA1_KD: 16,
    ETYPE_AES128_CTS_HMAC_SHA1_96: 17,
    ETYPE_AES256_CTS_HMAC_SHA1_96: 18,
    ETYPE_AES128_CTS_HMAC_SHA256_128: 19,
    ETYPE_AES256_CTS_HMAC_SHA384_192: 20,
    ETYPE_RC4_HMAC: 23,
    ETYPE_RC4_HMAC_EXP: 24,

    // Name Types (RFC 4120 Section 6.2)
    NT_UNKNOWN: 0,
    NT_PRINCIPAL: 1,
    NT_SRV_INST: 2,
    NT_SRV_HST: 3,
    NT_SRV_XHST: 4,
    NT_UID: 5,
    NT_ENTERPRISE: 10
  };

  var ETYPE_NAMES = {};
  ETYPE_NAMES[CONSTANTS.ETYPE_DES_CBC_CRC] = 'des-cbc-crc (1 - Deprecated)';
  ETYPE_NAMES[CONSTANTS.ETYPE_DES_CBC_MD5] = 'des-cbc-md5 (3 - Deprecated)';
  ETYPE_NAMES[CONSTANTS.ETYPE_DES3_CBC_SHA1_KD] = 'des3-cbc-sha1-kd (16 - Deprecated)';
  ETYPE_NAMES[CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA1_96] = 'aes128-cts-hmac-sha1-96 (17 - Modern)';
  ETYPE_NAMES[CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96] = 'aes256-cts-hmac-sha1-96 (18 - Zero-Trust Standard)';
  ETYPE_NAMES[CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA256_128] = 'aes128-cts-hmac-sha256-128 (19 - Modern)';
  ETYPE_NAMES[CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA384_192] = 'aes256-cts-hmac-sha384-192 (20 - Zero-Trust Suite B)';
  ETYPE_NAMES[CONSTANTS.ETYPE_RC4_HMAC] = 'rc4-hmac (23 - Vulnerable to Kerberoasting)';
  ETYPE_NAMES[CONSTANTS.ETYPE_RC4_HMAC_EXP] = 'rc4-hmac-exp (24 - Vulnerable)';

  // --- ASN.1 DER Helper Functions ---
  function strToBytes(str) {
    var out = [];
    str = str || '';
    for (var i = 0; i < str.length; i++) {
      out.push(str.charCodeAt(i) & 0xff);
    }
    return out;
  }

  function encodeLength(len) {
    if (len < 128) {
      return [len & 0x7f];
    }
    var bytes = [];
    var temp = len;
    while (temp > 0) {
      bytes.unshift(temp & 0xff);
      temp = temp >> 8;
    }
    bytes.unshift(0x80 | bytes.length);
    return bytes;
  }

  function encodeTLV(tag, valBytes) {
    valBytes = valBytes || [];
    var lenBytes = encodeLength(valBytes.length);
    return [tag].concat(lenBytes, valBytes);
  }

  function encodeInteger(val) {
    val = Math.floor(val);
    if (val === 0) return encodeTLV(0x02, [0x00]);
    var bytes = [];
    var isNegative = val < 0;
    if (isNegative) val = val >>> 0; // unsigned cast for simplicity if positive range

    var temp = val;
    while (temp > 0) {
      bytes.unshift(temp & 0xff);
      temp = temp >> 8;
    }
    // ASN.1 INTEGER requires leading zero if high bit is set for positive numbers
    if ((bytes[0] & 0x80) !== 0) {
      bytes.unshift(0x00);
    }
    return encodeTLV(0x02, bytes);
  }

  function encodeGeneralString(str) {
    return encodeTLV(0x1b, strToBytes(str));
  }

  function encodeOctetString(bytes) {
    return encodeTLV(0x04, bytes);
  }

  function encodeSequence(elements) {
    var combined = [];
    for (var i = 0; i < elements.length; i++) {
      combined = combined.concat(elements[i]);
    }
    return encodeTLV(0x30, combined);
  }

  function encodeContextTag(tagNum, valBytes) {
    // Constructed context-specific tag: 0xa0 | tagNum (for tags 0..30)
    var tag = 0xa0 | (tagNum & 0x1f);
    return encodeTLV(tag, valBytes);
  }

  function encodeApplicationTag(appNum, valBytes) {
    // Constructed application tag: 0x60 | appNum (for tags 0..30)
    var tag = 0x60 | (appNum & 0x1f);
    return encodeTLV(tag, valBytes);
  }

  function encodeGeneralizedTime(date) {
    date = date || new Date();
    var Y = date.getUTCFullYear();
    var M = String(date.getUTCMonth() + 1).padStart(2, '0');
    var D = String(date.getUTCDate()).padStart(2, '0');
    var h = String(date.getUTCHours()).padStart(2, '0');
    var m = String(date.getUTCMinutes()).padStart(2, '0');
    var s = String(date.getUTCSeconds()).padStart(2, '0');
    var timeStr = '' + Y + M + D + h + m + s + 'Z';
    return encodeTLV(0x18, strToBytes(timeStr));
  }

  // --- Kerberos Structure Builders (RFC 4120 Section 5) ---

  /**
   * PrincipalName ::= SEQUENCE {
   *     name-type       [0] Int32,
   *     name-string     [1] SEQUENCE OF KerberosString
   * }
   */
  function encodePrincipalName(nameType, nameParts) {
    nameType = nameType !== undefined ? nameType : CONSTANTS.NT_PRINCIPAL;
    nameParts = nameParts || ['administrator'];

    var t0 = encodeContextTag(0, encodeInteger(nameType));
    var seqParts = [];
    for (var i = 0; i < nameParts.length; i++) {
      seqParts.push(encodeGeneralString(nameParts[i]));
    }
    var t1 = encodeContextTag(1, encodeSequence(seqParts));
    return encodeSequence([t0, t1]);
  }

  /**
   * PA-DATA ::= SEQUENCE {
   *     padata-type     [1] Int32,
   *     padata-value    [2] OCTET STRING
   * }
   */
  function encodePAData(padataType, valBytes) {
    valBytes = valBytes || [];
    var t1 = encodeContextTag(1, encodeInteger(padataType));
    var t2 = encodeContextTag(2, encodeOctetString(valBytes));
    return encodeSequence([t1, t2]);
  }

  /**
   * EncryptedData ::= SEQUENCE {
   *     etype   [0] Int32,
   *     kvno    [1] UInt32 OPTIONAL,
   *     cipher  [2] OCTET STRING
   * }
   */
  function encodeEncryptedData(etype, kvno, cipherBytes) {
    etype = etype !== undefined ? etype : CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96;
    cipherBytes = cipherBytes || [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    var seq = [
      encodeContextTag(0, encodeInteger(etype))
    ];
    if (kvno !== undefined && kvno !== null) {
      seq.push(encodeContextTag(1, encodeInteger(kvno)));
    }
    seq.push(encodeContextTag(2, encodeOctetString(cipherBytes)));
    return encodeSequence(seq);
  }

  /**
   * Ticket ::= [APPLICATION 1] SEQUENCE {
   *     tkt-vno         [0] INTEGER (5),
   *     realm           [1] Realm,
   *     sname           [2] PrincipalName,
   *     enc-part        [3] EncryptedData
   * }
   */
  function encodeTicket(realm, snameParts, etype, kvno) {
    realm = realm || 'CORP.LOCAL';
    snameParts = snameParts || ['krbtgt', realm];
    etype = etype !== undefined ? etype : CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96;
    kvno = kvno !== undefined ? kvno : 2;

    var dummyCipher = [];
    for (var i = 0; i < 48; i++) {
      dummyCipher.push((i * 13 + 37) & 0xff);
    }

    var t0 = encodeContextTag(0, encodeInteger(5));
    var t1 = encodeContextTag(1, encodeGeneralString(realm));
    var t2 = encodeContextTag(2, encodePrincipalName(CONSTANTS.NT_SRV_INST, snameParts));
    var t3 = encodeContextTag(3, encodeEncryptedData(etype, kvno, dummyCipher));

    var ticketSeq = encodeSequence([t0, t1, t2, t3]);
    return encodeApplicationTag(1, ticketSeq);
  }

  /**
   * KDC-REQ-BODY ::= SEQUENCE {
   *     kdc-options             [0] KDCOptions,
   *     cname                   [1] PrincipalName OPTIONAL,
   *     realm                   [2] Realm,
   *     sname                   [3] PrincipalName OPTIONAL,
   *     from                    [4] KerberosTime OPTIONAL,
   *     till                    [5] KerberosTime,
   *     rtime                   [6] KerberosTime OPTIONAL,
   *     nonce                   [7] UInt32,
   *     etype                   [8] SEQUENCE OF Int32,
   *     addresses               [9] HostAddresses OPTIONAL,
   *     enc-authorization-data  [10] EncryptedData OPTIONAL,
   *     additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
   * }
   */
  function encodeKDCReqBody(opts) {
    opts = opts || {};
    var realm = opts.realm || 'CORP.LOCAL';
    var cnameParts = opts.cnameParts || ['alice'];
    var snameParts = opts.snameParts || ['krbtgt', realm];
    var nonce = opts.nonce || 0x3f9a71b2;
    var etypes = opts.etypes || [CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96, CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA1_96];
    var forwardable = opts.forwardable !== false;
    var renewable = opts.renewable !== false;

    // KDCOptions is a 32-bit BIT STRING: forwardable=bit 1 (0x40000000), renewable=bit 8 (0x00800000)
    var kdcOptVal = 0x00000000;
    if (forwardable) kdcOptVal |= 0x40000000;
    if (renewable) kdcOptVal |= 0x00800000;
    var kdcOptBytes = [
      (kdcOptVal >>> 24) & 0xff,
      (kdcOptVal >>> 16) & 0xff,
      (kdcOptVal >>> 8) & 0xff,
      kdcOptVal & 0xff
    ];
    // BIT STRING has leading unused-bits count (0)
    var kdcOptionsBitStr = encodeTLV(0x03, [0x00].concat(kdcOptBytes));

    var bodySeq = [
      encodeContextTag(0, kdcOptionsBitStr),
      encodeContextTag(1, encodePrincipalName(CONSTANTS.NT_PRINCIPAL, cnameParts)),
      encodeContextTag(2, encodeGeneralString(realm)),
      encodeContextTag(3, encodePrincipalName(opts.isTgs ? CONSTANTS.NT_SRV_INST : CONSTANTS.NT_SRV_INST, snameParts)),
      encodeContextTag(5, encodeGeneralizedTime(new Date(Date.now() + 10 * 3600 * 1000))), // 10h till
      encodeContextTag(7, encodeInteger(nonce))
    ];

    // etype sequence
    var etypeSeqParts = [];
    for (var i = 0; i < etypes.length; i++) {
      etypeSeqParts.push(encodeInteger(etypes[i]));
    }
    bodySeq.push(encodeContextTag(8, encodeSequence(etypeSeqParts)));

    return encodeSequence(bodySeq);
  }

  /**
   * Constructs an AS-REQ (Application 10) or TGS-REQ (Application 12)
   */
  function forgeKDCRequest(opts) {
    opts = opts || {};
    var isTgs = opts.msgType === CONSTANTS.MSG_TGS_REQ;
    var appTagNum = isTgs ? CONSTANTS.MSG_TGS_REQ : CONSTANTS.MSG_AS_REQ;
    var msgType = appTagNum;

    var padataList = [];
    if (opts.requirePreAuth !== false && !isTgs) {
      // PA-ENC-TIMESTAMP (type 2)
      var dummyEncTimestamp = [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78];
      var encTimestampObj = encodeEncryptedData(opts.preferredEtype || CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96, null, dummyEncTimestamp);
      padataList.push(encodePAData(CONSTANTS.PA_ENC_TIMESTAMP, encTimestampObj));

      // PA-PAC-REQUEST (type 128) - PAC requested = true
      var pacReqBytes = encodeSequence([encodeContextTag(0, [0x01, 0x01, 0xff])]); // Boolean true
      padataList.push(encodePAData(CONSTANTS.PA_PAC_REQUEST, pacReqBytes));
    } else if (isTgs) {
      // PA-TGS-REQ (type 1) - contains AP-REQ with TGT Ticket
      var tgtTicket = encodeTicket(opts.realm, ['krbtgt', opts.realm || 'CORP.LOCAL'], CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96, 2);
      padataList.push(encodePAData(CONSTANTS.PA_TGS_REQ, tgtTicket));
    }

    var reqBody = encodeKDCReqBody({
      realm: opts.realm || 'CORP.LOCAL',
      cnameParts: opts.cnameParts || ['alice'],
      snameParts: opts.snameParts || (isTgs ? ['MSSQLSvc', 'sql01.corp.local:1433'] : ['krbtgt', opts.realm || 'CORP.LOCAL']),
      nonce: opts.nonce || 0x3f9a71b2,
      etypes: opts.etypes || [CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96, CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA1_96],
      isTgs: isTgs
    });

    var kdcReqFields = [
      encodeContextTag(1, encodeInteger(5)),               // pvno = 5
      encodeContextTag(2, encodeInteger(msgType))          // msg-type
    ];

    if (padataList.length > 0) {
      var paSeq = [];
      for (var p = 0; p < padataList.length; p++) {
        paSeq.push(padataList[p]);
      }
      kdcReqFields.push(encodeContextTag(3, encodeSequence(paSeq)));
    }

    kdcReqFields.push(encodeContextTag(4, reqBody));

    var topSeq = encodeSequence(kdcReqFields);
    var wireBytes = encodeApplicationTag(appTagNum, topSeq);

    return {
      wireBytes: wireBytes,
      totalLength: wireBytes.length,
      msgType: msgType,
      msgTypeName: isTgs ? 'KRB_TGS_REQ (12)' : 'KRB_AS_REQ (10)',
      realm: opts.realm || 'CORP.LOCAL',
      client: (opts.cnameParts || ['alice']).join('/'),
      service: (opts.snameParts || (isTgs ? ['MSSQLSvc', 'sql01.corp.local:1433'] : ['krbtgt', opts.realm || 'CORP.LOCAL'])).join('/'),
      preAuthEnforced: opts.requirePreAuth !== false,
      padataCount: padataList.length,
      etypes: opts.etypes || [CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96, CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA1_96]
    };
  }

  /**
   * Formats byte array as Wireshark-style hexadecimal dump
   */
  function formatHexDump(bytes) {
    var lines = [];
    for (var i = 0; i < bytes.length; i += 16) {
      var chunk = bytes.slice(i, i + 16);
      var offsetHex = i.toString(16).padStart(4, '0');
      var hexParts = [];
      var asciiParts = [];

      for (var j = 0; j < 16; j++) {
        if (j < chunk.length) {
          var b = chunk[j];
          hexParts.push(b.toString(16).padStart(2, '0'));
          asciiParts.push((b >= 32 && b <= 126) ? String.fromCharCode(b) : '.');
        } else {
          hexParts.push('  ');
          asciiParts.push(' ');
        }
      }

      var hexFormatted = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ');
      lines.push(offsetHex + '   ' + hexFormatted + '   |' + asciiParts.join('') + '|');
    }
    return lines.join('\n');
  }

  /**
   * Evaluates Kerberoasting & AS-REP Roasting Vulnerability Risk
   */
  function evaluateKerberoastRisk(serviceName, accountType, etype, pwdEntropyBits) {
    serviceName = serviceName || 'MSSQLSvc/sql.corp.local';
    accountType = accountType || 'USER_SPN'; // 'USER_SPN', 'GMSA', 'COMPUTER_ACCOUNT'
    etype = parseInt(etype, 10) || CONSTANTS.ETYPE_RC4_HMAC;
    pwdEntropyBits = parseInt(pwdEntropyBits, 10) || 45;

    var isRC4 = (etype === CONSTANTS.ETYPE_RC4_HMAC || etype === CONSTANTS.ETYPE_RC4_HMAC_EXP);
    var isDES = (etype === CONSTANTS.ETYPE_DES_CBC_CRC || etype === CONSTANTS.ETYPE_DES_CBC_MD5);
    var isGMSA = (accountType === 'GMSA');
    var isComputer = (accountType === 'COMPUTER_ACCOUNT');

    if (isGMSA) {
      return {
        vulnerable: false,
        riskLevel: 'LOW',
        verdict: 'IMMUNE (Group Managed Service Account - gMSA)',
        description: 'Account uses automated 120-character random password rotation managed by Active Directory KDC.',
        crackingTime: '> 100,000 Years (Computationally Infeasible)',
        recommendation: 'Maintain current gMSA deployment across all application service accounts.'
      };
    }

    if (isComputer) {
      return {
        vulnerable: false,
        riskLevel: 'LOW',
        verdict: 'LOW_RISK (Machine / Computer Account)',
        description: 'Computer accounts default to 120-byte pseudo-random passwords rotated every 30 days.',
        crackingTime: '> 50,000 Years against RTX 4090 Hashcat cluster',
        recommendation: 'Ensure machine account password change interval is active (DisablePasswordChange=0).'
      };
    }

    if (isDES) {
      return {
        vulnerable: true,
        riskLevel: 'CRITICAL',
        verdict: 'IMMEDIATELY COMPROMISED (DES-CBC-MD5 / 56-bit Key)',
        description: 'Single-DES can be cracked on modern cloud GPUs in under 3 minutes using precomputed rainbow tables.',
        crackingTime: '< 3 Minutes (Instant Ransomware / Lateral Movement)',
        recommendation: 'Purge DES encryption types via GPO: "Network security: Configure encryption types allowed for Kerberos".'
      };
    }

    if (isRC4) {
      var estHours = Math.pow(2, Math.max(0, pwdEntropyBits - 32)) / (5000000000 / 3600);
      var crackDisplay = estHours < 1 ? '< 15 Minutes' : (estHours < 24 ? Math.round(estHours) + ' Hours' : Math.round(estHours / 24) + ' Days');
      return {
        vulnerable: true,
        riskLevel: 'HIGH',
        verdict: 'HIGHLY VULNERABLE TO KERBEROASTING (RC4-HMAC Type 23)',
        description: 'TGS tickets are encrypted with legacy MD4/NTLM hash of user-configured password. Fast hashcat cracking rates (~5 billion/sec on 8x RTX 4090).',
        crackingTime: crackDisplay + ' (at ' + pwdEntropyBits + ' bits password entropy)',
        recommendation: 'Migrate SPN to Group Managed Service Account (gMSA) or enforce AES256_HMAC_SHA1 with a 32+ character random password.'
      };
    }

    // AES-128 / AES-256
    return {
      vulnerable: pwdEntropyBits < 64,
      riskLevel: pwdEntropyBits < 64 ? 'MEDIUM' : 'LOW',
      verdict: pwdEntropyBits < 64 ? 'MODERATE (AES-CTS with Human Password)' : 'STRONG (AES-256 with High-Entropy Key)',
      description: 'AES Kerberos tickets require PBKDF2-HMAC-SHA1 key derivation (4,096 iterations), slowing hashcat cracking speeds by 10,000x compared to RC4.',
      crackingTime: pwdEntropyBits < 64 ? 'Several Months to Years' : '> 10,000 Years',
      recommendation: 'Enforce AES256-only service tickets and transition to gMSA.'
    };
  }

  return {
    CONSTANTS: CONSTANTS,
    ETYPE_NAMES: ETYPE_NAMES,
    encodeTLV: encodeTLV,
    encodeInteger: encodeInteger,
    encodeGeneralString: encodeGeneralString,
    encodeSequence: encodeSequence,
    encodeContextTag: encodeContextTag,
    encodeApplicationTag: encodeApplicationTag,
    encodePrincipalName: encodePrincipalName,
    encodePAData: encodePAData,
    encodeEncryptedData: encodeEncryptedData,
    encodeTicket: encodeTicket,
    encodeKDCReqBody: encodeKDCReqBody,
    forgeKDCRequest: forgeKDCRequest,
    formatHexDump: formatHexDump,
    evaluateKerberoastRisk: evaluateKerberoastRisk
  };
});
