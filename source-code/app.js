/**
 * KerberosForge Pro - Web Application Controller
 * Handles UI interactions, presets, live ASN.1 DER dissection, and reactive synthesis.
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  var currentPlatform = 'krb5';

  // Presets definition
  var PRESETS = {
    enterprise: {
      msgType: 10,
      realmName: 'CORP.LOCAL',
      clientPrincipal: 'alice',
      servicePrincipal: 'krbtgt/CORP.LOCAL',
      nonceHex: '0x3f9a71b2',
      preferredEtype: 18, // aes256
      preAuth: true,
      accountType: 'GMSA',
      pwdEntropy: 128,
      gmsa: true,
      pacValidation: true,
      rbcd: true,
      pkinit: true,
      fastArmor: true,
      kdcCopp: true,
      krbtgtAge: 45,
      clockSkew: 1,
      allowedEtypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
      accountsWithoutPreAuth: 0,
      userSpnAccountCount: 0
    },
    hybrid: {
      msgType: 12,
      realmName: 'IPA.CORP.NET',
      clientPrincipal: 'bob',
      servicePrincipal: 'HTTP/webapp.ipa.corp.net',
      nonceHex: '0x18ac49b0',
      preferredEtype: 18,
      preAuth: true,
      accountType: 'COMPUTER_ACCOUNT',
      pwdEntropy: 110,
      gmsa: true,
      pacValidation: true,
      rbcd: true,
      pkinit: false,
      fastArmor: true,
      kdcCopp: true,
      krbtgtAge: 90,
      clockSkew: 2,
      allowedEtypes: ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'],
      accountsWithoutPreAuth: 0,
      userSpnAccountCount: 0
    },
    vulnerable: {
      msgType: 12,
      realmName: 'LEGACY.CORP',
      clientPrincipal: 'intruder',
      servicePrincipal: 'MSSQLSvc/sql01.legacy.corp:1433',
      nonceHex: '0x00000001',
      preferredEtype: 23, // rc4-hmac
      preAuth: false,
      accountType: 'USER_SPN',
      pwdEntropy: 38,
      gmsa: false,
      pacValidation: false,
      rbcd: false,
      pkinit: false,
      fastArmor: false,
      kdcCopp: false,
      krbtgtAge: 450,
      clockSkew: 120,
      allowedEtypes: ['rc4-hmac', 'des-cbc-md5'],
      accountsWithoutPreAuth: 12,
      userSpnAccountCount: 8
    }
  };

  // DOM Elements
  var elMsgType = document.getElementById('msgType');
  var elRealmName = document.getElementById('realmName');
  var elClientPrincipal = document.getElementById('clientPrincipal');
  var elServicePrincipal = document.getElementById('servicePrincipal');
  var elNonceHex = document.getElementById('nonceHex');
  var elPreferredEtype = document.getElementById('preferredEtype');
  var elChkPreAuth = document.getElementById('chkPreAuth');

  var elAccountType = document.getElementById('accountType');
  var elPwdEntropy = document.getElementById('pwdEntropy');
  var elKerberoastResult = document.getElementById('kerberoastResult');

  var elChkGmsa = document.getElementById('chkGmsa');
  var elChkPacValidation = document.getElementById('chkPacValidation');
  var elChkRbcd = document.getElementById('chkRbcd');
  var elChkPkinit = document.getElementById('chkPkinit');
  var elChkFastArmor = document.getElementById('chkFastArmor');
  var elChkKdcCopp = document.getElementById('chkKdcCopp');
  var elKrbtgtAge = document.getElementById('krbtgtAge');
  var elClockSkew = document.getElementById('clockSkew');

  var elHexDumpDisplay = document.getElementById('hexDumpDisplay');
  var elConfigDisplay = document.getElementById('configDisplay');
  var elAuditSummaryBadge = document.getElementById('auditSummaryBadge');
  var elScorecardBanner = document.getElementById('scorecardBanner');
  var elGradeCircle = document.getElementById('gradeCircle');
  var elScorecardHeadline = document.getElementById('scorecardHeadline');
  var elScorecardSub = document.getElementById('scorecardSub');
  var elFindingsContainer = document.getElementById('findingsContainer');

  var btnCopyHex = document.getElementById('btnCopyHex');
  var btnCopyConfig = document.getElementById('btnCopyConfig');

  function parseHexOrInt(val) {
    if (typeof val === 'string' && val.trim().startsWith('0x')) {
      return parseInt(val.trim(), 16) || 0;
    }
    return parseInt(val, 10) || 0;
  }

  function getFormValues() {
    var etypeVal = parseInt(elPreferredEtype.value, 10) || 18;
    var allowedEtypes = [];
    if (etypeVal === 18) allowedEtypes = ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'];
    else if (etypeVal === 17) allowedEtypes = ['aes128-cts-hmac-sha1-96'];
    else if (etypeVal === 23) allowedEtypes = ['rc4-hmac'];
    else if (etypeVal === 1) allowedEtypes = ['des-cbc-crc', 'des-cbc-md5'];

    return {
      msgType: parseInt(elMsgType.value, 10) || 10,
      realm: (elRealmName.value || 'CORP.LOCAL').trim().toUpperCase(),
      clientPrincipal: (elClientPrincipal.value || 'alice').trim(),
      servicePrincipal: (elServicePrincipal.value || 'krbtgt/CORP.LOCAL').trim(),
      nonce: parseHexOrInt(elNonceHex.value) || 0x3f9a71b2,
      preferredEtype: etypeVal,
      preAuthEnforced: elChkPreAuth.checked,
      accountType: elAccountType.value,
      pwdEntropy: parseInt(elPwdEntropy.value, 10) || 64,
      gmsaDeployed: elChkGmsa.checked,
      userSpnAccountCount: elChkGmsa.checked ? 0 : 5,
      pacValidationEnforced: elChkPacValidation.checked,
      pacSignaturesActive: elChkPacValidation.checked,
      delegationType: elChkRbcd.checked ? 'RBCD' : 'UNCONSTRAINED',
      pkinitEnabled: elChkPkinit.checked,
      fastArmoring: elChkFastArmor.checked,
      kdcCoppActive: elChkKdcCopp.checked,
      krbtgtAgeDays: parseInt(elKrbtgtAge.value, 10) || 45,
      clockSkewSeconds: parseInt(elClockSkew.value, 10) || 1,
      ntsNtpActive: true,
      allowedEtypes: allowedEtypes,
      accountsWithoutPreAuth: elChkPreAuth.checked ? 0 : 5
    };
  }

  function applyPreset(p) {
    elMsgType.value = p.msgType;
    elRealmName.value = p.realmName;
    elClientPrincipal.value = p.clientPrincipal;
    elServicePrincipal.value = p.servicePrincipal;
    elNonceHex.value = p.nonceHex;
    elPreferredEtype.value = p.preferredEtype;
    elChkPreAuth.checked = p.preAuth;

    elAccountType.value = p.accountType;
    elPwdEntropy.value = p.pwdEntropy;

    elChkGmsa.checked = p.gmsa;
    elChkPacValidation.checked = p.pacValidation;
    elChkRbcd.checked = p.rbcd;
    elChkPkinit.checked = p.pkinit;
    elChkFastArmor.checked = p.fastArmor;
    elChkKdcCopp.checked = p.kdcCopp;
    elKrbtgtAge.value = p.krbtgtAge;
    elClockSkew.value = p.clockSkew;

    updateUI();
  }

  function updateUI() {
    var vals = getFormValues();

    // 1. Evaluate Kerberoast Risk
    var roaster = KerberosProtocolEngine.evaluateKerberoastRisk(
      vals.servicePrincipal,
      vals.accountType,
      vals.preferredEtype,
      vals.pwdEntropy
    );

    if (roaster.vulnerable) {
      elKerberoastResult.className = 'risk-box risk-box-vuln';
      elKerberoastResult.innerHTML = '<div><strong>Verdict:</strong> ' + roaster.verdict + ' (Risk: ' + roaster.riskLevel + ')</div>' +
        '<div><strong>Cracking Difficulty:</strong> ' + roaster.crackingTime + '</div>' +
        '<div style="font-size:11px; margin-top:3px;"><strong>Remediation:</strong> ' + roaster.recommendation + '</div>';
    } else {
      elKerberoastResult.className = 'risk-box risk-box-safe';
      elKerberoastResult.innerHTML = '<div><strong>Verdict:</strong> ' + roaster.verdict + ' (Risk: ' + roaster.riskLevel + ')</div>' +
        '<div><strong>Cracking Difficulty:</strong> ' + roaster.crackingTime + '</div>' +
        '<div style="font-size:11px; margin-top:3px;">' + roaster.recommendation + '</div>';
    }

    // 2. Build Packet & Hex Dump
    var cnameParts = vals.clientPrincipal.split('/');
    var snameParts = vals.servicePrincipal.split('/');
    var forged = KerberosProtocolEngine.forgeKDCRequest({
      msgType: vals.msgType,
      realm: vals.realm,
      cnameParts: cnameParts,
      snameParts: snameParts,
      nonce: vals.nonce,
      preferredEtype: vals.preferredEtype,
      requirePreAuth: vals.preAuthEnforced,
      etypes: vals.allowedEtypes.map(function (e) {
        if (e.indexOf('256') !== -1) return KerberosProtocolEngine.CONSTANTS.ETYPE_AES256_CTS_HMAC_SHA1_96;
        if (e.indexOf('128') !== -1) return KerberosProtocolEngine.CONSTANTS.ETYPE_AES128_CTS_HMAC_SHA1_96;
        if (e.indexOf('rc4') !== -1) return KerberosProtocolEngine.CONSTANTS.ETYPE_RC4_HMAC;
        return KerberosProtocolEngine.CONSTANTS.ETYPE_DES_CBC_MD5;
      })
    });

    var dumpText = KerberosProtocolEngine.formatHexDump(forged.wireBytes);
    var banner = '[RFC 4120 ' + forged.msgTypeName + ' | Realm: ' + forged.realm + ' | Client: ' + forged.client + ' | Service: ' + forged.service + ' | Wire: ' + forged.totalLength + ' Bytes | Pre-Auth: ' + (forged.preAuthEnforced ? 'PA-ENC-TIMESTAMP' : 'NONE') + ']\n\n';
    elHexDumpDisplay.textContent = banner + dumpText;

    // 3. Security Audit Evaluation
    var audit = KerberosSecurityAuditor.auditConfiguration(vals);
    elAuditSummaryBadge.textContent = audit.score + ' / 100 PTS (' + audit.grade + ')';
    elGradeCircle.textContent = audit.grade;

    if (audit.grade === 'F' || audit.grade === 'C') {
      elScorecardBanner.className = 'scorecard-banner fail-banner';
      elGradeCircle.className = 'grade-circle fail-circle';
      elAuditSummaryBadge.className = 'badge badge-gold';
      elScorecardHeadline.textContent = 'High Domain Identity Exposure (Grade ' + audit.grade + ')';
      elScorecardSub.textContent = audit.failCount + ' critical identity security failures detected. Domain vulnerable to Kerberoasting, AS-REP Roasting, and Golden Ticket lateral movement.';
    } else {
      elScorecardBanner.className = 'scorecard-banner';
      elGradeCircle.className = 'grade-circle';
      elAuditSummaryBadge.className = 'badge badge-emerald';
      elScorecardHeadline.textContent = 'Zero-Trust Domain Identity Compliance (Grade ' + audit.grade + ')';
      elScorecardSub.textContent = audit.passCount + '/10 controls passed. Strong AES-256 ciphers, universal pre-authentication, gMSA immunity, and PAC validation.';
    }

    // Render findings
    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(function (f) {
      var item = document.createElement('div');
      item.className = 'finding-item';

      var scoreColor = f.status === 'PASS' ? '#34d399' : (f.status === 'WARNING' ? '#fbbf24' : '#fb7185');
      var statusIcon = f.status === 'PASS' ? '✓' : (f.status === 'WARNING' ? '⚠' : '✗');

      item.innerHTML = '<div class="finding-top">' +
        '<div class="finding-title" style="color:' + scoreColor + '">' + statusIcon + ' ' + f.title + '</div>' +
        '<div class="finding-score" style="color:' + scoreColor + '">' + f.earned + ' / ' + f.weight + ' pts</div>' +
        '</div>' +
        '<div class="finding-text">' + f.details + '</div>' +
        '<div class="finding-remediation">Remediation: ' + f.remediation + '</div>';
      elFindingsContainer.appendChild(item);
    });

    // 4. Synthesize Multi-Platform Configurations
    renderPlatformConfig(vals);
  }

  function renderPlatformConfig(vals) {
    vals = vals || getFormValues();
    var synthesized = '';
    if (currentPlatform === 'krb5') {
      synthesized = KerberosConfigSynthesizer.synthesizeKrb5Conf(vals);
    } else if (currentPlatform === 'kdc') {
      synthesized = KerberosConfigSynthesizer.synthesizeKdcConf(vals);
    } else if (currentPlatform === 'sssd') {
      synthesized = KerberosConfigSynthesizer.synthesizeSSSD(vals);
    } else if (currentPlatform === 'powershell') {
      synthesized = KerberosConfigSynthesizer.synthesizePowerShellAD(vals);
    } else if (currentPlatform === 'prometheus') {
      synthesized = KerberosConfigSynthesizer.synthesizePrometheusAlerts(vals);
    }
    elConfigDisplay.textContent = synthesized;
  }

  // Event Listeners for inputs
  var inputs = [
    elMsgType, elRealmName, elClientPrincipal, elServicePrincipal, elNonceHex, elPreferredEtype, elChkPreAuth,
    elAccountType, elPwdEntropy,
    elChkGmsa, elChkPacValidation, elChkRbcd, elChkPkinit, elChkFastArmor, elChkKdcCopp, elKrbtgtAge, elClockSkew
  ];

  inputs.forEach(function (inp) {
    if (!inp) return;
    inp.addEventListener('input', updateUI);
    inp.addEventListener('change', updateUI);
  });

  // Preset Buttons
  document.getElementById('btnPresetEnterprise').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.enterprise);
  });

  document.getElementById('btnPresetHybrid').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.hybrid);
  });

  document.getElementById('btnPresetVulnerable').addEventListener('click', function () {
    document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
    this.classList.add('active');
    applyPreset(PRESETS.vulnerable);
  });

  // Copy buttons
  btnCopyHex.addEventListener('click', function () {
    navigator.clipboard.writeText(elHexDumpDisplay.textContent).then(function () {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(function () { btnCopyHex.textContent = 'Copy Hex Dump'; }, 2000);
    });
  });

  btnCopyConfig.addEventListener('click', function () {
    navigator.clipboard.writeText(elConfigDisplay.textContent).then(function () {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(function () { btnCopyConfig.textContent = 'Copy Configuration'; }, 2000);
    });
  });

  // Platform tabs
  document.querySelectorAll('.tabs-nav .tab-btn').forEach(function (tab) {
    tab.addEventListener('click', function () {
      document.querySelectorAll('.tabs-nav .tab-btn').forEach(function (t) { t.classList.remove('active'); });
      this.classList.add('active');
      currentPlatform = this.getAttribute('data-platform');
      renderPlatformConfig();
    });
  });

  // Initial Run
  applyPreset(PRESETS.enterprise);
});
