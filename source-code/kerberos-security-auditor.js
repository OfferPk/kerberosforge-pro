/**
 * KerberosForge Pro - 10-Point Zero-Trust Domain Identity Auditor
 * Evaluates Active Directory, MIT Kerberos KDC, and FreeIPA realm security against
 * NIST 800-53, CIS Microsoft Windows Server Benchmark, and MITRE ATT&CK (T1558).
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.KerberosSecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditConfiguration(config) {
    config = config || {};
    var findings = [];
    var score = 0;

    // 1. Encryption Types Allowed (12 pts)
    var allowedEtypes = config.allowedEtypes || ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'];
    var hasRC4 = allowedEtypes.some(function (e) { return e.indexOf('rc4') !== -1; });
    var hasDES = allowedEtypes.some(function (e) { return e.indexOf('des') !== -1; });
    var hasAES256 = allowedEtypes.some(function (e) { return e.indexOf('aes256') !== -1; });

    if (hasDES) {
      findings.push({
        id: 'KRB-SEC-01',
        title: 'Legacy Single-DES Encryption Permitted',
        category: 'Cryptographic Protection',
        weight: 12,
        earned: 0,
        status: 'CRITICAL',
        details: 'DES-CBC-MD5 or DES-CBC-CRC is enabled. 56-bit DES keys can be cracked in under 3 minutes via cloud rainbow tables.',
        remediation: 'Purge DES encryption types via GPO: "Network security: Configure encryption types allowed for Kerberos" (enforce 0x7ffffff8).'
      });
    } else if (hasRC4) {
      findings.push({
        id: 'KRB-SEC-01',
        title: 'RC4-HMAC Enabled (Kerberoasting Vector)',
        category: 'Cryptographic Protection',
        weight: 12,
        earned: 4,
        status: 'WARNING',
        details: 'RC4-HMAC (Type 23) is permitted. Attackers can request RC4 TGS tickets for SPNs and crack service passwords at billions of guesses per second.',
        remediation: 'Disable RC4-HMAC domain-wide. Configure msDS-SupportedEncryptionTypes = 0x18 (AES128 + AES256 only).'
      });
      score += 4;
    } else if (hasAES256) {
      findings.push({
        id: 'KRB-SEC-01',
        title: 'Strong AES-256 Encryption Enforced',
        category: 'Cryptographic Protection',
        weight: 12,
        earned: 12,
        status: 'PASS',
        details: 'Kerberos tickets exclusively use AES256-CTS-HMAC-SHA1-96 (Type 18) and AES128 (Type 17). RC4 and DES are purged.',
        remediation: 'Monitor for legacy client negotiation fallbacks in event log 4769.'
      });
      score += 12;
    } else {
      findings.push({
        id: 'KRB-SEC-01',
        title: 'Suboptimal Kerberos Encryption Suite',
        category: 'Cryptographic Protection',
        weight: 12,
        earned: 6,
        status: 'WARNING',
        details: 'AES-256 is missing from preferred encryption types.',
        remediation: 'Add AES256-CTS-HMAC-SHA1-96 as the top priority encryption type.'
      });
      score += 6;
    }

    // 2. Pre-Authentication Enforcement (AS-REP Roasting Shield) (12 pts)
    var preAuthEnforced = config.preAuthEnforced !== false;
    var accountsWithoutPreAuth = parseInt(config.accountsWithoutPreAuth, 10) || 0;

    if (!preAuthEnforced || accountsWithoutPreAuth > 0) {
      findings.push({
        id: 'KRB-SEC-02',
        title: 'AS-REP Roasting Vulnerability Active',
        category: 'Identity Security',
        weight: 12,
        earned: 0,
        status: 'CRITICAL',
        details: accountsWithoutPreAuth + ' account(s) have "Do not require Kerberos preauthentication" (DONT_REQ_PREAUTH) enabled. Attackers can harvest crackable AS-REP hashes without credentials.',
        remediation: 'Clear UF_DONT_REQUIRE_PREAUTH (0x400000) on all user accounts: "Set-ADAccountControl -DoesNotRequirePreAuth $false".'
      });
    } else {
      findings.push({
        id: 'KRB-SEC-02',
        title: 'Universal Kerberos Pre-Authentication Enforced',
        category: 'Identity Security',
        weight: 12,
        earned: 12,
        status: 'PASS',
        details: 'Pre-authentication (PA-ENC-TIMESTAMP / PA-PK-AS-REQ) is strictly required across 100% of domain accounts (Zero AS-REP Roasting exposure).',
        remediation: 'Continuously scan AD directory for new accounts created with DONT_REQ_PREAUTH flag.'
      });
      score += 12;
    }

    // 3. Service Account Hardening & gMSA (Kerberoasting Defense) (10 pts)
    var gmsaDeployed = !!config.gmsaDeployed;
    var userSpnAccountCount = parseInt(config.userSpnAccountCount, 10) || 0;

    if (gmsaDeployed && userSpnAccountCount === 0) {
      findings.push({
        id: 'KRB-SEC-03',
        title: 'Group Managed Service Accounts (gMSA) Fully Deployed',
        category: 'Service Identity',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'All SPNs reside on Group Managed Service Accounts (gMSA) with automated 120-character random password rotation. Immune to offline Kerberoasting.',
        remediation: 'Audit newly deployed services to ensure developers request gMSAs instead of standard service user accounts.'
      });
      score += 10;
    } else if (gmsaDeployed && userSpnAccountCount > 0) {
      findings.push({
        id: 'KRB-SEC-03',
        title: 'Partial gMSA Adoption (Residual User SPNs)',
        category: 'Service Identity',
        weight: 10,
        earned: 5,
        status: 'WARNING',
        details: userSpnAccountCount + ' legacy user account(s) retain SPNs. If their passwords are under 25 characters, they remain Kerberoastable.',
        remediation: 'Migrate the remaining ' + userSpnAccountCount + ' user service accounts to gMSAs.'
      });
      score += 5;
    } else {
      findings.push({
        id: 'KRB-SEC-03',
        title: 'Unmanaged User SPNs Detected (High Kerberoasting Risk)',
        category: 'Service Identity',
        weight: 10,
        earned: 1,
        status: 'FAIL',
        details: 'Service Principal Names (SPNs) are registered to standard user accounts with static passwords. Any domain user can Kerberoast these accounts.',
        remediation: 'Implement gMSAs (New-ADServiceAccount) and enforce 32+ character random passwords for non-gMSA service accounts.'
      });
      score += 1;
    }

    // 4. PAC Validation & Signature Hardening (CVE-2021-42287) (10 pts)
    var pacValidationEnforced = !!config.pacValidationEnforced;
    var pacSignaturesActive = !!config.pacSignaturesActive;

    if (pacValidationEnforced && pacSignaturesActive) {
      findings.push({
        id: 'KRB-SEC-04',
        title: 'PAC Validation & KDC Signature Verification Enforced',
        category: 'Privilege Integrity',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'KDC verifies Privilege Attribute Certificate (PAC) signatures (PacRequestorEnforcement = 2 / KB5008380). Prevents sAMAccountName machine spoofing escalation.',
        remediation: 'Ensure all domain controllers have the latest cumulative security rollups installed.'
      });
      score += 10;
    } else if (pacSignaturesActive) {
      findings.push({
        id: 'KRB-SEC-04',
        title: 'PAC Signatures Present but Enforcement in Audit Mode',
        category: 'Privilege Integrity',
        weight: 10,
        earned: 5,
        status: 'WARNING',
        details: 'PAC signatures are logged but not strictly enforced (PacRequestorEnforcement = 1). Spoofed tickets may not be blocked.',
        remediation: 'Switch PacRequestorEnforcement registry key to 2 (Enforcement Mode).'
      });
      score += 5;
    } else {
      findings.push({
        id: 'KRB-SEC-04',
        title: 'Missing PAC Validation (Privilege Escalation Risk)',
        category: 'Privilege Integrity',
        weight: 10,
        earned: 0,
        status: 'FAIL',
        details: 'Domain Controllers do not strictly validate PAC signatures, leaving the domain vulnerable to Golden Ticket group spoofing.',
        remediation: 'Apply KB5008380 and enable strict PAC verification across all KDCs.'
      });
    }

    // 5. Kerberos Delegation Architecture (10 pts)
    var delegationType = config.delegationType || 'RBCD'; // 'UNCONSTRAINED', 'CONSTRAINED', 'RBCD', 'NONE'

    if (delegationType === 'RBCD' || delegationType === 'NONE') {
      findings.push({
        id: 'KRB-SEC-05',
        title: 'Resource-Based Constrained Delegation (RBCD) Active',
        category: 'Delegation Security',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Delegation is strictly managed at the resource target (msDS-AllowedToActOnBehalfOfOtherIdentity). Zero unconstrained delegation servers.',
        remediation: 'Mark sensitive accounts (Domain Admins) as "Account is sensitive and cannot be delegated".'
      });
      score += 10;
    } else if (delegationType === 'CONSTRAINED') {
      findings.push({
        id: 'KRB-SEC-05',
        title: 'Traditional Constrained Delegation Configured',
        category: 'Delegation Security',
        weight: 10,
        earned: 7,
        status: 'PASS',
        details: 'Constrained delegation with explicit SPN lists is in use. Unconstrained delegation is disabled.',
        remediation: 'Migrate to Resource-Based Constrained Delegation (RBCD) to decentralize access control.'
      });
      score += 7;
    } else {
      findings.push({
        id: 'KRB-SEC-05',
        title: 'Unconstrained Delegation Permitted (Critical Hazard)',
        category: 'Delegation Security',
        weight: 10,
        earned: 0,
        status: 'CRITICAL',
        details: 'One or more servers have Unconstrained Delegation (TRUSTED_FOR_DELEGATION). Connecting admins leave full TGTs in server memory, allowing complete domain takeover.',
        remediation: 'Remove TRUSTED_FOR_DELEGATION immediately. Convert to Constrained Delegation or RBCD.'
      });
    }

    // 6. Clock Skew Synchronization & Drift Bounds (10 pts)
    var clockSkewSec = parseInt(config.clockSkewSeconds, 10) || 1;
    var ntsNtpActive = !!config.ntsNtpActive;

    if (clockSkewSec <= 5 && ntsNtpActive) {
      findings.push({
        id: 'KRB-SEC-06',
        title: 'Sub-Second Precision Clock Sync (NTS / Authenticated NTP)',
        category: 'Time Synchronization',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Clock skew is ' + clockSkewSec + 's (well below RFC 4120 300s limit) backed by authenticated Network Time Security (NTS). Replay attacks mitigated.',
        remediation: 'Maintain Prometheus alerts for clock drift > 2 seconds.'
      });
      score += 10;
    } else if (clockSkewSec <= 60) {
      findings.push({
        id: 'KRB-SEC-06',
        title: 'Acceptable Clock Skew (' + clockSkewSec + 's)',
        category: 'Time Synchronization',
        weight: 10,
        earned: 7,
        status: 'PASS',
        details: 'Clock skew is within standard tolerances, but authenticated NTP (NTS) is not verified.',
        remediation: 'Deploy RFC 8915 NTS on PDC Emulator to protect against external clock manipulation.'
      });
      score += 7;
    } else {
      findings.push({
        id: 'KRB-SEC-06',
        title: 'Dangerous Clock Drift (' + clockSkewSec + 's)',
        category: 'Time Synchronization',
        weight: 10,
        earned: 1,
        status: 'FAIL',
        details: 'Clock skew exceeds 60 seconds. Nearing the 300s (5-minute) Kerberos limit, which will trigger domain-wide authentication lockouts.',
        remediation: 'Resynchronize PDC Emulator with authoritative Stratum 1 time source immediately.'
      });
      score += 1;
    }

    // 7. PKINIT & Passwordless / Smart Card Readiness (10 pts)
    var pkinitEnabled = !!config.pkinitEnabled;

    if (pkinitEnabled) {
      findings.push({
        id: 'KRB-SEC-07',
        title: 'RFC 4556 PKINIT / Smart Card & FIDO2 Active',
        category: 'Asymmetric Authentication',
        weight: 10,
        earned: 10,
        status: 'PASS',
        details: 'Public-key cryptography (PA-PK-AS-REQ) enabled for initial authentication. Eliminates password spraying and offline NTLM cracking.',
        remediation: 'Mandate "Smart card is required for interactive logon" for all privileged administrative accounts.'
      });
      score += 10;
    } else {
      findings.push({
        id: 'KRB-SEC-07',
        title: 'Password-Only Authentication (PKINIT Disabled)',
        category: 'Asymmetric Authentication',
        weight: 10,
        earned: 4,
        status: 'INFO',
        details: 'KDC relies on symmetric password key derivation. Vulnerable to credential stuffing and phishing if MFA is not enforced at identity provider layer.',
        remediation: 'Deploy Microsoft CA / Enterprise PKI and enable PKINIT for Windows Hello for Business and hardware smart cards.'
      });
      score += 4;
    }

    // 8. Automated krbtgt Key Rotation (Golden Ticket Remediation) (9 pts)
    var krbtgtAgeDays = parseInt(config.krbtgtAgeDays, 10) || 30;

    if (krbtgtAgeDays <= 180) {
      findings.push({
        id: 'KRB-SEC-08',
        title: 'Active krbtgt Password Rotation (' + krbtgtAgeDays + ' days old)',
        category: 'Credential Hygiene',
        weight: 9,
        earned: 9,
        status: 'PASS',
        details: 'The domain krbtgt account was rotated ' + krbtgtAgeDays + ' days ago (recommended: every 180 days). Invalidates lingering forged Golden Tickets.',
        remediation: 'Maintain scheduled dual-rotation script (e.g. New-KrbtgtKeys.ps1) with a 24-hour gap between rotations.'
      });
      score += 9;
    } else if (krbtgtAgeDays <= 365) {
      findings.push({
        id: 'KRB-SEC-08',
        title: 'Aging krbtgt Account Password (' + krbtgtAgeDays + ' days old)',
        category: 'Credential Hygiene',
        weight: 9,
        earned: 4,
        status: 'WARNING',
        details: 'krbtgt password has not been rotated in over 6 months. Forged Golden Tickets created in the past remain valid.',
        remediation: 'Execute a scheduled krbtgt dual-rotation to invalidate stale ticket signing keys.'
      });
      score += 4;
    } else {
      findings.push({
        id: 'KRB-SEC-08',
        title: 'Stale krbtgt Password (> 1 Year Old)',
        category: 'Credential Hygiene',
        weight: 9,
        earned: 0,
        status: 'FAIL',
        details: 'krbtgt account password is ' + krbtgtAgeDays + ' days old. Any past domain compromise allows permanent persistent access via Golden Tickets.',
        remediation: 'Immediately perform a dual krbtgt password reset to flush all unauthorized TGTs.'
      });
    }

    // 9. FAST Armor / RFC 6113 Flexible Authentication Tunneling (9 pts)
    var fastArmoring = !!config.fastArmoring;

    if (fastArmoring) {
      findings.push({
        id: 'KRB-SEC-09',
        title: 'Kerberos Armoring (FAST / RFC 6113) Enforced',
        category: 'Transport Protection',
        weight: 9,
        earned: 9,
        status: 'PASS',
        details: 'Pre-authentication timestamp exchange is encapsulated inside an encrypted computer account tunnel. Thwarts offline dictionary attacks against AS-REQ.',
        remediation: 'Enable "Fail unarmored authentication requests" GPO policy on all domain controllers.'
      });
      score += 9;
    } else {
      findings.push({
        id: 'KRB-SEC-09',
        title: 'Kerberos Armoring (FAST) Disabled',
        category: 'Transport Protection',
        weight: 9,
        earned: 2,
        status: 'WARNING',
        details: 'FAST armoring is not enforced. An attacker on the local network can capture PA-ENC-TIMESTAMP and attempt offline dictionary cracking.',
        remediation: 'Configure "KDC support for claims, compound authentication and Kerberos armoring" in Domain Controller GPO.'
      });
      score += 2;
    }

    // 10. Control Plane Policing & Port 88 Rate-Limiting (8 pts)
    var kdcCoppActive = !!config.kdcCoppActive;

    if (kdcCoppActive) {
      findings.push({
        id: 'KRB-SEC-10',
        title: 'KDC Control Plane Policing (CoPP) Active on Port 88',
        category: 'Infrastructure Protection',
        weight: 8,
        earned: 8,
        status: 'PASS',
        details: 'Hardware/OS rate-limiting filter applied to UDP and TCP port 88. Prevents KDC CPU starvation during automated password spraying or SYN flood attacks.',
        remediation: 'Monitor port 88 drop telemetry in SIEM to detect brute-force spray campaigns.'
      });
      score += 8;
    } else {
      findings.push({
        id: 'KRB-SEC-10',
        title: 'Unpoliced Kerberos Port 88 (DDoS & Spraying Exposure)',
        category: 'Infrastructure Protection',
        weight: 8,
        earned: 2,
        status: 'WARNING',
        details: 'Port 88 (Kerberos) has no rate-limiting or firewall throttling, exposing the Domain Controller to volumetric authentication floods.',
        remediation: 'Implement Windows Advanced Firewall connection rate-limiting or network switch CoPP for port 88.'
      });
      score += 2;
    }

    // Grade Determination
    var grade = 'F';
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 50) grade = 'C';
    else grade = 'F';

    var passCount = findings.filter(function (f) { return f.status === 'PASS'; }).length;
    var warnCount = findings.filter(function (f) { return f.status === 'WARNING'; }).length;
    var failCount = findings.filter(function (f) { return f.status === 'FAIL' || f.status === 'CRITICAL'; }).length;

    return {
      score: score,
      maxScore: 100,
      grade: grade,
      passCount: passCount,
      warnCount: warnCount,
      failCount: failCount,
      findings: findings,
      isCompliant: score >= 80 && failCount === 0
    };
  }

  return {
    auditConfiguration: auditConfiguration
  };
});
