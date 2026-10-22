# KerberosForge Pro \- Architecture & Technical Specification

> **IETF RFC 4120 (Kerberos V5) & RFC 4556 (PKINIT) Zero-Trust Domain Identity Studio & Wireframe Engine**

---

## 1\. Executive Summary & Protocol Overview

The **Kerberos Network Authentication Service (Kerberos V5)**, standardized in **IETF RFC 4120**, is the cornerstone authentication and authorization protocol securing virtually all enterprise identity domains worldwide. It powers:

- **Microsoft Active Directory (AD)**: The primary directory and authentication service across over 90% of Fortune 500 corporations.  
- **Linux Enterprise Identity**: Integrated Linux domains via SSSD, FreeIPA, and MIT Kerberos KDC clusters.  
- **Big Data & Cloud Analytics**: Distributed infrastructure including Apache Hadoop, Kafka, and Kubernetes enterprise secrets.

Kerberos operates on a trusted third-party model (the **Key Distribution Center / KDC**), which comprises:

1. **Authentication Service (AS)**: Issues a Ticket Granting Ticket (TGT) upon verifying user pre-authentication.  
2. **Ticket Granting Service (TGS)**: Issues Service Tickets (TGS) to access specific network services (e.g. MSSQL, CIFS, HTTP).

   \[ Client \] \----(1) AS-REQ (Pre-Auth Timestamp)----\> \[ KDC / AS \]

   \[ Client \] \<---(2) AS-REP (TGT \+ Session Key)------- \[ KDC / AS \]

   

   \[ Client \] \----(3) TGS-REQ (TGT \+ Authenticator)---\> \[ KDC / TGS \]

   \[ Client \] \<---(4) TGS-REP (Service Ticket)-------- \[ KDC / TGS \]

   

   \[ Client \] \----(5) AP-REQ (Service Ticket)---------\> \[ Target Service \]

   \[ Client \] \<---(6) AP-REP (Mutual Auth \- Optional)-- \[ Target Service \]

---

## 2\. RFC 4120 ASN.1 DER Wireframe Format

Kerberos messages transmitted over UDP or TCP port 88 are encoded strictly in **ASN.1 DER (Distinguished Encoding Rules)** using Application and Context-Specific tags:

### 2.1 Top-Level Application Tags

- `[APPLICATION 10]` (`0x6a`): `AS-REQ` (Authentication Service Request)  
- `[APPLICATION 11]` (`0x6b`): `AS-REP` (Authentication Service Reply)  
- `[APPLICATION 12]` (`0x6c`): `TGS-REQ` (Ticket Granting Service Request)  
- `[APPLICATION 13]` (`0x6d`): `TGS-REP` (Ticket Granting Service Reply)  
- `[APPLICATION 14]` (`0x6e`): `AP-REQ` (Application Authentication Request)  
- `[APPLICATION 1]` (`0x61`): `Ticket`

### 2.2 KDC-REQ Structure Definition

KDC-REQ ::= SEQUENCE {

    pvno            \[1\] INTEGER (5),

    msg-type        \[2\] INTEGER (10 \-- AS-REQ \-- | 12 \-- TGS-REQ \--),

    padata          \[3\] SEQUENCE OF PA-DATA OPTIONAL,

    req-body        \[4\] KDC-REQ-BODY

}

KDC-REQ-BODY ::= SEQUENCE {

    kdc-options             \[0\] KDCOptions,

    cname                   \[1\] PrincipalName OPTIONAL,

    realm                   \[2\] Realm,

    sname                   \[3\] PrincipalName OPTIONAL,

    from                    \[4\] KerberosTime OPTIONAL,

    till                    \[5\] KerberosTime,

    rtime                   \[6\] KerberosTime OPTIONAL,

    nonce                   \[7\] UInt32,

    etype                   \[8\] SEQUENCE OF Int32,

    addresses               \[9\] HostAddresses OPTIONAL,

    enc-authorization-data  \[10\] EncryptedData OPTIONAL,

    additional-tickets      \[11\] SEQUENCE OF Ticket OPTIONAL

}

---

## 3\. Threat Modeling & Attack Surface Decomposition

### 3.1 Kerberoasting (MITRE ATT\&CK T1558.003)

- **Mechanism**: Any domain-authenticated user requests a Service Ticket (`KRB_TGS_REQ`) for a Service Principal Name (SPN) registered to a user account. The KDC generates a ticket encrypted with the service account's secret key (derived from its password).  
- **Vulnerability**: If the service account utilizes legacy `rc4-hmac` (Type 23\) encryption, the attacker extracts the ciphertext and cracks it offline using hashcat (`hashcat -m 13100`) at billions of attempts per second without generating any further domain controller events.  
- **Zero-Trust Remediation**:  
  1. Enforce **Group Managed Service Accounts (gMSA)** featuring 120-character random passwords rotated automatically by Active Directory.  
  2. Configure `msDS-SupportedEncryptionTypes = 0x18` (AES128 \+ AES256 only) to mandate PBKDF2-HMAC-SHA1 key derivation (slowing cracking by \$\> 10,000\\times\$).

### 3.2 AS-REP Roasting (MITRE ATT\&CK T1558.004)

- **Mechanism**: When an account has `DONT_REQ_PREAUTH` (UF\_DONT\_REQUIRE\_PREAUTH \= 0x400000) enabled, an unauthenticated attacker requests an `AS-REQ` without providing an encrypted timestamp. The KDC returns an `AS-REP` containing the user's encrypted ticket.  
- **Vulnerability**: The attacker cracks the encrypted portion offline (`hashcat -m 18200`) without triggering bad-password count lockouts on the domain controller.  
- **Zero-Trust Remediation**: Universal enforcement of Kerberos pre-authentication (`Set-ADAccountControl -DoesNotRequirePreAuth $false`).

### 3.3 Golden Ticket & Silver Ticket Forgery

- **Golden Ticket**: Attacker obtains the NTLM or AES key of the domain `krbtgt` account, enabling offline synthesis of valid Ticket Granting Tickets (TGT) with forged Domain Admins PAC group memberships valid for 10 years.  
- **Silver Ticket**: Attacker obtains the password hash of a specific service account (e.g. CIFS/server or MSSQLSvc/db), forging TGS tickets directly without contacting the KDC.  
- **Zero-Trust Remediation**:  
  1. Scheduled **dual-rotation of the `krbtgt` password** every 180 days.  
  2. Enforcement of **KDC PAC Validation** (KB5008380 / CVE-2021-42287 `PacRequestorEnforcement = 2`).

### 3.4 Unconstrained vs. Constrained vs. Resource-Based Delegation

- **Unconstrained Delegation (`TRUSTED_FOR_DELEGATION`)**: The server receives and caches the user's complete TGT in memory. Compromise of the server compromises all connected users (including Domain Admins).  
- **Resource-Based Constrained Delegation (RBCD)**: Configured directly on the target resource (`msDS-AllowedToActOnBehalfOfOtherIdentity`), limiting delegation strictly to trusted callers.

---

## 4\. 10-Point Zero-Trust Domain Identity Audit Framework

| Control ID | Evaluation Domain | Weight | Compliance Target |
| :---- | :---- | :---: | :---- |
| **KRB-SEC-01** | Encryption Types Allowed | 12 pts | AES-256/AES-128 enforced; RC4-HMAC and DES purged. |
| **KRB-SEC-02** | Universal Pre-Authentication | 12 pts | Zero accounts with `DONT_REQ_PREAUTH` active. |
| **KRB-SEC-03** | gMSA Deployment (Kerberoasting) | 10 pts | 100% SPNs bound to gMSAs or 32+ character random keys. |
| **KRB-SEC-04** | PAC Validation & Signature Gating | 10 pts | Strict PAC validation (`PacRequestorEnforcement = 2`). |
| **KRB-SEC-05** | Kerberos Delegation Architecture | 10 pts | Resource-Based Constrained Delegation (RBCD); 0 unconstrained. |
| **KRB-SEC-06** | Clock Skew Synchronization | 10 pts | Clock drift \$\\le 5\$s backed by Network Time Security (NTS). |
| **KRB-SEC-07** | PKINIT / Passwordless Readiness | 10 pts | RFC 4556 PKINIT / FIDO2 / Windows Hello for Business active. |
| **KRB-SEC-08** | Automated `krbtgt` Key Rotation | 9 pts | `krbtgt` rotated within last 180 days (dual-rotation). |
| **KRB-SEC-09** | Kerberos Armoring (FAST / RFC 6113\) | 9 pts | Pre-authentication wrapped in computer account tunnel. |
| **KRB-SEC-10** | KDC Control Plane Policing (Port 88\) | 8 pts | Hardware / firewall rate-limiting on UDP/TCP port 88\. |

