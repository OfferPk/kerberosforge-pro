# KerberosForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for Active Directory administrators, identity architects, and SecOps engineers deploying Zero-Trust Kerberos V5 (RFC 4120).**

---

## 1\. Quickstart: Web Application Studio

The **KerberosForge Pro Web Studio** runs 100% client-side with zero external dependencies. Open `source-code/index.html` in any modern web browser:

\# Optional local web server

cd product\_116/source-code

python3 \-m http.server 8080

\# Navigate to http\://localhost:8080

### Studio Interface Overview:

1. **Security Presets Bar**:  
   - **Enterprise Zero-Trust AD (Grade A+)**: AES-256 only, gMSA immunity, PAC validation, and FAST armoring.  
   - **Hybrid Cloud FreeIPA (Grade A)**: Linux SSSD and FreeIPA cross-realm integration.  
   - **Vulnerable Legacy Domain (Grade F)**: Legacy RC4, missing pre-auth, and unconstrained delegation.  
2. **KDC Request Parameters**: Adjust message type (AS-REQ vs TGS-REQ), realm name, client principal, and Service Principal Name (SPN).  
3. **Kerberoasting & Pre-Auth Evaluator**: Real-time evaluation of offline cracking feasibility across account types and password entropy levels.  
4. **10-Point Zero-Trust Scorecard**: Real-time audit scoring (0–100%, Grades A+ to F) with granular remediation steps.  
5. **ASN.1 DER Dissector & Wireshark Hex Formatter**: Visual breakdown of KDC request wireframes with 1-click clipboard export.  
6. **Multi-Platform Synthesizer**: Instant production configuration generation for Linux `krb5.conf`, MIT KDC `kdc.conf`, Linux `sssd.conf`, PowerShell AD Hardening, and Prometheus alert rules.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/kerberosforge-cli.py`) operates in Linux/macOS/Windows environments with zero external dependencies:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/kerberosforge-cli.py \--dissect

### 2.2 Running 10-Point Zero-Trust Domain Audits

\# Audit Enterprise Active Directory preset

./build/kerberosforge-cli.py \--preset build/presets/enterprise-zerotrust-ad.json \--audit

\# Audit vulnerable legacy domain configuration

./build/kerberosforge-cli.py \--preset build/presets/vulnerable-legacy-domain.json \--audit

### 2.3 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for Wireshark inspection or network test suites:

./build/kerberosforge-cli.py \--preset build/presets/enterprise-zerotrust-ad.json \--pcap enterprise-kerberos.pcap

\# Inspect with tcpdump

tcpdump \-n \-r enterprise-kerberos.pcap

### 2.4 Synthesizing Production Device Stanzas

\# Output Linux krb5.conf

./build/kerberosforge-cli.py \--preset build/presets/enterprise-zerotrust-ad.json \--synthesize krb5

\# Output all platforms

./build/kerberosforge-cli.py \--preset build/presets/enterprise-zerotrust-ad.json \--synthesize all

### 2.5 Automated CI/CD Pipeline Gating (`--strict`)

Integrate KerberosForge Pro into CI/CD pipelines to audit identity infrastructure code:

\- name: Audit Kerberos Realm Configuration

  run: |

    python3 build/kerberosforge-cli.py \\

      \--preset build/presets/production-ad.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+). Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F). Pipeline halts.*

---

## 3\. Production Deployment & Hardening Guide

### 3.1 Active Directory Domain Hardening (PowerShell)

\# 1\. Enforce AES-256 and AES-128 (Disable RC4 & DES)

Set-ItemProperty \-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters" \`

  \-Name "SupportedEncryptionTypes" \-Value 0x18

\# 2\. Remediate AS-REP Roasting Accounts

Get-ADUser \-Filter {DoesNotRequirePreAuth \-eq \$True} | ForEach-Object {

    Set-ADAccountControl \-Identity \$\_ \-DoesNotRequirePreAuth \$False

}

\# 3\. Enforce Strict PAC Validation (CVE-2021-42287)

Set-ItemProperty \-Path "HKLM:\\System\\CurrentControlSet\\Services\\Kdc" \`

  \-Name "PacRequestorEnforcement" \-Value 2

Set-ItemProperty \-Path "HKLM:\\System\\CurrentControlSet\\Services\\Kdc" \`

  \-Name "KdcArmoringEnforcement" \-Value 1

### 3.2 Linux SSSD Configuration (`sssd.conf`)

\[domain/corp.local\]

id\_provider \= ad

auth\_provider \= ad

ad\_domain \= corp.local

krb5\_realm \= CORP.LOCAL

krb5\_validate \= true

krb5\_store\_password\_if\_offline \= false

krb5\_use\_fast \= try

krb5\_fast\_principal \= host/corp.local

ad\_gpo\_access\_control \= enforcing

---

## 4\. Troubleshooting & High-Impact Failure Codes

1. **`KRB_AP_ERR_SKEW (Clock skew too great)`**:  
   - *Cause*: Time difference between KDC and client exceeds 300 seconds (5 minutes).  
   - *Resolution*: Verify NTP/NTS synchronization: `w32tm /resync /force` or `chronyc makestep`.  
2. **`KDC_ERR_ETYPE_NOSUPP (KDC has no support for encryption type)`**:  
   - *Cause*: Client requested legacy DES or RC4, which has been purged on the KDC.  
   - *Resolution*: Update client `krb5.conf` to include `aes256-cts-hmac-sha1-96`.  
3. **`KDC_ERR_PREAUTH_FAILED (Pre-authentication information was invalid)`**:  
   - *Cause*: Incorrect password entered, or clock skew corrupted the encrypted timestamp.  
   - *Resolution*: Verify user credentials and check local machine clock.