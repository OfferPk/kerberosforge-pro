/**
 * KerberosForge Pro - Multi-Platform Configuration Synthesizer
 * Generates production-hardened Kerberos V5 stanzas for Active Directory,
 * MIT Kerberos KDC, Linux SSSD, PowerShell AD Hardening, and Prometheus Alerting.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.KerberosConfigSynthesizer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeKrb5Conf(cfg) {
    var realm = (cfg.realm || 'CORP.LOCAL').toUpperCase();
    var kdc = cfg.kdcHost || 'dc01.corp.local';
    var kdc2 = cfg.kdcHostSecondary || 'dc02.corp.local';

    var out = [];
    out.push('# =================================================================');
    out.push('# Zero-Trust Linux Kerberos V5 Client Configuration (/etc/krb5.conf)');
    out.push('# Standards: IETF RFC 4120 | RFC 3962 | RFC 4556 | CIS Hardened');
    out.push('# =================================================================');
    out.push('[libdefaults]');
    out.push('    default_realm = ' + realm);
    out.push('    dns_lookup_realm = false');
    out.push('    dns_lookup_kdc = true');
    out.push('    ticket_lifetime = 24h');
    out.push('    renew_lifetime = 7d');
    out.push('    forwardable = true');
    out.push('    rdns = false');
    out.push('    clockskew = 300');
    out.push('');
    out.push('    # --- Cryptographic Suite B Hardening (Purge RC4 & DES) ---');
    out.push('    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96');
    out.push('    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96');
    out.push('    permitted_enctypes   = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96');
    out.push('');
    out.push('    # --- FAST Armoring (RFC 6113) ---');
    out.push('    canonicalize = true');
    out.push('    qualify_shortname = ""');
    out.push('');
    out.push('[realms]');
    out.push('    ' + realm + ' = {');
    out.push('        kdc = ' + kdc + ':88');
    out.push('        kdc = ' + kdc2 + ':88');
    out.push('        admin_server = ' + kdc + ':749');
    out.push('        default_domain = ' + realm.toLowerCase());
    out.push('        pkinit_anchors = FILE:/etc/pki/ca-trust/source/anchors/DomainCA.crt');
    out.push('        pkinit_require_eku = true');
    out.push('        pkinit_require_krbtgt_otherName = true');
    out.push('    }');
    out.push('');
    out.push('[domain_realm]');
    out.push('    .' + realm.toLowerCase() + ' = ' + realm);
    out.push('    ' + realm.toLowerCase() + ' = ' + realm);
    return out.join('\n');
  }

  function synthesizeKdcConf(cfg) {
    var realm = (cfg.realm || 'CORP.LOCAL').toUpperCase();

    var out = [];
    out.push('# =================================================================');
    out.push('# MIT Kerberos KDC Production Configuration (kdc.conf)');
    out.push('# Standards: RFC 4120 Section 5 | RFC 4556 PKINIT | RFC 6113 FAST');
    out.push('# =================================================================');
    out.push('[kdcdefaults]');
    out.push('    kdc_ports = 88');
    out.push('    kdc_tcp_ports = 88');
    out.push('');
    out.push('[realms]');
    out.push('    ' + realm + ' = {');
    out.push('        master_key_type = aes256-cts');
    out.push('        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal');
    out.push('        acl_file = /var/kerberos/krb5kdc/kadm5.acl');
    out.push('        dict_file = /usr/share/dict/words');
    out.push('        admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab');
    out.push('        max_life = 24h 0m 0s');
    out.push('        max_renewable_life = 7d 0m 0s');
    out.push('        reject_bad_transit = true');
    out.push('');
    out.push('        # --- PKINIT (Public Key Cryptography) ---');
    out.push('        pkinit_identity = FILE:/var/kerberos/krb5kdc/kdc.pem,/var/kerberos/krb5kdc/kdckey.pem');
    out.push('        pkinit_anchors = FILE:/etc/pki/ca-trust/source/anchors/DomainCA.crt');
    out.push('        pkinit_require_eku = true');
    out.push('        pkinit_require_krbtgt_otherName = true');
    out.push('        pkinit_allow_enckey_contract = false');
    out.push('    }');
    return out.join('\n');
  }

  function synthesizeSSSD(cfg) {
    var realm = (cfg.realm || 'CORP.LOCAL').toUpperCase();
    var domain = realm.toLowerCase();

    var out = [];
    out.push('# =================================================================');
    out.push('# Linux System Security Services Daemon (sssd.conf)');
    out.push('# Hardened Active Directory & Kerberos Integration');
    out.push('# =================================================================');
    out.push('[sssd]');
    out.push('services = nss, pam');
    out.push('config_file_version = 2');
    out.push('domains = ' + domain);
    out.push('');
    out.push('[domain/' + domain + ']');
    out.push('id_provider = ad');
    out.push('auth_provider = ad');
    out.push('chpass_provider = ad');
    out.push('access_provider = ad');
    out.push('');
    out.push('# --- Active Directory Identity & DNS ---');
    out.push('ad_domain = ' + domain);
    out.push('krb5_realm = ' + realm);
    out.push('realmd_tags = manages-system joined-with-adcli');
    out.push('cache_credentials = true');
    out.push('');
    out.push('# --- Zero-Trust Kerberos Ticket Validation ---');
    out.push('krb5_validate = true');
    out.push('krb5_store_password_if_offline = false');
    out.push('krb5_use_fast = try');
    out.push('krb5_fast_principal = host/' + domain);
    out.push('ad_gpo_access_control = enforcing');
    out.push('ldap_id_mapping = true');
    out.push('use_fully_qualified_names = false');
    out.push('fallback_homedir = /home/%u@%d');
    out.push('default_shell = /bin/bash');
    return out.join('\n');
  }

  function synthesizePowerShellAD(cfg) {
    var out = [];
    out.push('# =================================================================');
    out.push('# Active Directory Domain Kerberos Hardening Script (PowerShell)');
    out.push('# Mitigates Kerberoasting, AS-REP Roasting, and CVE-2021-42287 PAC Spoofing');
    out.push('# =================================================================');
    out.push('');
    out.push('# 1. Enforce AES-256 and AES-128 Domain-Wide (Purge DES & RC4)');
    out.push('Write-Host "Enforcing AES-256 Kerberos Encryption via Group Policy..." -ForegroundColor Cyan');
    out.push('$GpoRegPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"');
    out.push('If (-not (Test-Path $GpoRegPath)) { New-Item -Path $GpoRegPath -Force | Out-Null }');
    out.push('# 0x18 = AES128_HMAC_SHA1 (0x8) | AES256_HMAC_SHA1 (0x10)');
    out.push('Set-ItemProperty -Path $GpoRegPath -Name "SupportedEncryptionTypes" -Value 0x18');
    out.push('');
    out.push('# 2. Audit and Fix Accounts with Pre-Authentication Disabled (AS-REP Roasting)');
    out.push('Write-Host "Auditing accounts with DONT_REQ_PREAUTH..." -ForegroundColor Yellow');
    out.push('$VulnUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}');
    out.push('foreach ($u in $VulnUsers) {');
    out.push('    Write-Warning "Remediating vulnerable account: $($u.SamAccountName)"');
    out.push('    Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $False');
    out.push('}');
    out.push('');
    out.push('# 3. Enforce Strict PAC Validation & Requestor Signature (CVE-2021-42287 / KB5008380)');
    out.push('Write-Host "Enforcing PAC Requestor Verification (Mode 2)..." -ForegroundColor Cyan');
    out.push('$KdcRegPath = "HKLM:\\System\\CurrentControlSet\\Services\\Kdc"');
    out.push('Set-ItemProperty -Path $KdcRegPath -Name "PacRequestorEnforcement" -Value 2');
    out.push('Set-ItemProperty -Path $KdcRegPath -Name "KdcArmoringEnforcement" -Value 1');
    out.push('');
    out.push('# 4. Audit User Accounts with SPNs (Kerberoasting Targets)');
    out.push('Write-Host "Listing non-gMSA user accounts with registered SPNs..." -ForegroundColor Yellow');
    out.push('Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes |');
    out.push('    Select-Object Name, SamAccountName, ServicePrincipalName, msDS-SupportedEncryptionTypes | Format-Table -AutoSize');
    return out.join('\n');
  }

  function synthesizePrometheusAlerts(cfg) {
    var out = [];
    out.push('# =================================================================');
    out.push('# Prometheus Kerberos V5 / Active Directory Security Alerting Rules');
    out.push('# =================================================================');
    out.push('groups:');
    out.push('  - name: kerberos_zero_trust_alerts');
    out.push('    rules:');
    out.push('      - alert: KerberosKDCUnreachable');
    out.push('        expr: probe_success{instance=~".*:88"} == 0');
    out.push('        for: 1m');
    out.push('        labels:');
    out.push('          severity: critical');
    out.push('        annotations:');
    out.push('          summary: "Kerberos KDC {{ $labels.instance }} unreachable"');
    out.push('          description: "Domain Controller failed TCP/UDP port 88 probes for over 60 seconds."');
    out.push('');
    out.push('      - alert: KerberoastingActivitySpike');
    out.push('        expr: rate(windows_eventlog_4769_rc4_total[5m]) > 5');
    out.push('        for: 2m');
    out.push('        labels:');
    out.push('          severity: critical');
    out.push('        annotations:');
    out.push('          summary: "Abnormal Kerberoasting spike detected (RC4 TGS Ticket Requests)"');
    out.push('          description: "High rate of Event 4769 with encryption type 0x17 (RC4-HMAC) indicating active offline hash extraction."');
    out.push('');
    out.push('      - alert: ASREPRoastingAttempt');
    out.push('        expr: increase(windows_eventlog_4768_no_preauth_total[10m]) > 0');
    out.push('        labels:');
    out.push('          severity: high');
    out.push('        annotations:');
    out.push('          summary: "AS-REQ ticket requested without pre-authentication"');
    out.push('          description: "Event 4768 logged with Pre-Auth Type 0 on non-exempt user account."');
    out.push('');
    out.push('      - alert: KerberosClockSkewHigh');
    out.push('        expr: abs(node_timex_offset_seconds) > 5');
    out.push('        for: 3m');
    out.push('        labels:');
    out.push('          severity: warning');
    out.push('        annotations:');
    out.push('          summary: "Host clock skew exceeds 5 seconds"');
    out.push('          description: "Host time drifting towards the 300-second Kerberos ticket invalidation threshold."');
    return out.join('\n');
  }

  return {
    synthesizeKrb5Conf: synthesizeKrb5Conf,
    synthesizeKdcConf: synthesizeKdcConf,
    synthesizeSSSD: synthesizeSSSD,
    synthesizePowerShellAD: synthesizePowerShellAD,
    synthesizePrometheusAlerts: synthesizePrometheusAlerts
  };
});
