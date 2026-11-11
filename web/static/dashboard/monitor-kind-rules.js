import {
  checkModeField, dnsHostField, dnsRecordTypeField, dnsServerField, dnsTargetRow, expectedStatusField,
  sdnsEndpointField, sdnsEndpointHint, sdnsFamilyRow, sdnsHostField, sdnsMethodField, sdnsMethodRow,
  sdnsRecordTypeField, sdnsTargetRow, sdnsTransportField,
  expectedStatusRow, expectedTextField, expectedTextHintField, expectedTextLabelField,
  expectedTextRow, httpHostField, httpMethodField, httpPathField, httpPortField, httpSchemeField,
  httpSkipVerifyField, httpSkipVerifyLabelField, httpSkipVerifyRow, httpsBodyRow, httpsCheckModeRow,
  httpsFamilyRow, httpsHeadersRow, httpsJsonPathRow, httpsMethodRow, httpsModeRow, httpsTargetRow,
  httpsVerifyRow, icmpFamilyRow, jsonPathExpectedField, jsonPathField, kindField, mailFamilyRow,
  mailHostField, mailPortField, mailTargetRow, mailVerifyField, mailVerifyLabelField, mailVerifyRow,
  promComparisonField, promExpectedValueField, promQueryField, promQueryRow, promThresholdRow,
  grpcServiceField, grpcServiceRow,
  requestBodyField, requestHeadersField, targetField, targetHintField, targetRow, tcpFamilyRow,
  tcpHostField, tcpPortField, tcpTargetRow, tlsModeField, tlsModeRow, udpCheckField, udpCheckRow,
  udpFamilyRow, udpHostField, udpPortField, udpTargetRow, useHTTPSField, useHTTPSLabelField,
  verifyCertField, verifyCertLabelField
} from './dom.js';
import {
  expectedKeywordsHintFallback, expectedKeywordsOptionalFallback, monitorSkipCertFallback,
  monitorTCPHandshakeFallback, monitorVerifyCertFallback, tr
} from './i18n.js';
import {
  syncHTTPSFamilyMode, syncICMPFamilyMode, syncMailFamilyMode, syncSDNSFamilyMode, syncTCPFamilyMode,
  syncUDPFamilyMode, syncUDPPortSuggestion, syncWhoisTargetDisclaimer
} from './monitor-family-sync.js';
import { normalizeSDNSTransport, sdnsUsesHTTP } from './monitor-target.js';
import { syncHeartbeatRows } from './monitor-heartbeat.js';
import { normalizeUDPCheck } from './monitor-target.js';

export const applyKindRules = () => {
  if (!kindField || !tlsModeRow || !httpsModeRow || !httpsVerifyRow || !expectedStatusRow || !expectedTextRow || !tlsModeField || !expectedStatusField || !expectedTextField || !useHTTPSField || !verifyCertField) {
    return;
  }

  const kind = kindField.value;
  const isHTTPMonitor = kind === 'https';
  const isTCPMonitor = kind === 'tcp';
  const isICMPMonitor = kind === 'icmp';
  const isMail = kind === 'smtp' || kind === 'imap';
  const isDNS = kind === 'dns';
  const isSDNS = kind === 'sdns';
  const isUDP = kind === 'udp';
  const isWhois = kind === 'whois';
  const isHeartbeat = kind === 'heartbeat';
  const isPrometheus = kind === 'prometheus' || kind === 'prom';
  const isGRPC = kind === 'grpc';
  const udpCheckMode = normalizeUDPCheck(udpCheckField?.value);
  const supportsTCPTLSChecks = isTCPMonitor || isGRPC;
  const isHTTPSEnabled = isHTTPMonitor && String(httpSchemeField?.value || 'https').toLowerCase() !== 'http';
  const mailTLSSelection = String(tlsModeField?.value || '').toLowerCase();
  const mailEncryptionEnabled = isMail && (mailTLSSelection === 'tls' || mailTLSSelection === 'starttls');
  const showExpectedText = isHTTPMonitor || isDNS || isSDNS;
  const httpsTLSOnly = isHTTPMonitor && String(checkModeField?.value || 'http').toLowerCase() === 'tls';
  const httpsContentChecks = isHTTPMonitor && !httpsTLSOnly;

  if (targetRow) {
    targetRow.hidden = isTCPMonitor || isHTTPMonitor || isUDP || isMail || isDNS || isSDNS || isHeartbeat || isGRPC;
  }
  if (httpsTargetRow) {
    httpsTargetRow.hidden = !isHTTPMonitor;
  }
  if (tcpTargetRow) {
    tcpTargetRow.hidden = !(isTCPMonitor || isGRPC);
  }
  if (promQueryRow) {
    promQueryRow.hidden = !isPrometheus;
  }
  if (promThresholdRow) {
    promThresholdRow.hidden = !isPrometheus;
  }
  if (grpcServiceRow) {
    grpcServiceRow.hidden = !isGRPC;
  }
  if (dnsTargetRow) {
    dnsTargetRow.hidden = !isDNS;
  }
  if (sdnsTargetRow) {
    sdnsTargetRow.hidden = !isSDNS;
  }
  if (mailTargetRow) {
    mailTargetRow.hidden = !isMail;
  }
  if (udpCheckRow) {
    udpCheckRow.hidden = !isUDP;
  }
  if (udpTargetRow) {
    udpTargetRow.hidden = !isUDP;
  }
  if (targetField) {
    targetField.required = !isTCPMonitor && !isHTTPMonitor && !isUDP && !isMail && !isDNS && !isSDNS && !isHeartbeat && !isGRPC;
  }
  if (promQueryField) {
    promQueryField.required = isPrometheus;
  }
  if (httpHostField) {
    httpHostField.required = isHTTPMonitor;
  }
  if (httpPortField) {
    httpPortField.required = false;
  }
  if (tcpHostField) {
    tcpHostField.required = isTCPMonitor || isGRPC;
  }
  if (tcpPortField) {
    tcpPortField.required = isTCPMonitor || isGRPC;
  }
  if (dnsHostField) {
    dnsHostField.required = isDNS;
  }
  if (sdnsHostField) {
    sdnsHostField.required = isSDNS;
  }
  if (sdnsEndpointField) {
    sdnsEndpointField.required = isSDNS;
  }
  if (mailHostField) {
    mailHostField.required = isMail;
  }
  if (mailPortField) {
    mailPortField.required = isMail;
  }
  if (udpHostField) {
    udpHostField.required = isUDP;
  }
  if (udpPortField) {
    udpPortField.required = isUDP;
  }

  tlsModeRow.hidden = !isMail;
  httpsModeRow.hidden = !supportsTCPTLSChecks;
  httpsVerifyRow.hidden = !supportsTCPTLSChecks || !useHTTPSField.checked;
  if (mailVerifyRow) {
    mailVerifyRow.hidden = !mailEncryptionEnabled;
  }
  if (httpSkipVerifyRow) {
    httpSkipVerifyRow.hidden = !isHTTPMonitor || !isHTTPSEnabled;
  }
  if (httpsCheckModeRow) {
    httpsCheckModeRow.hidden = !isHTTPMonitor || !isHTTPSEnabled;
  }
  if (httpsMethodRow) {
    httpsMethodRow.hidden = !httpsContentChecks;
  }
  if (httpsHeadersRow) {
    httpsHeadersRow.hidden = !httpsContentChecks;
  }
  if (httpsBodyRow) {
    const method = String(httpMethodField?.value || 'GET').toUpperCase();
    httpsBodyRow.hidden = !httpsContentChecks || method === 'GET' || method === 'HEAD';
  }
  if (httpsJsonPathRow) {
    httpsJsonPathRow.hidden = !httpsContentChecks;
  }
  expectedStatusRow.hidden = !httpsContentChecks;
  expectedTextRow.hidden = httpsContentChecks ? false : !showExpectedText || isHTTPMonitor;

  if (!isHTTPMonitor) {
    if (checkModeField) checkModeField.value = 'http';
    if (httpMethodField) httpMethodField.value = 'GET';
    if (requestHeadersField) requestHeadersField.value = '';
    if (requestBodyField) requestBodyField.value = '';
    if (jsonPathField) jsonPathField.value = '';
    if (jsonPathExpectedField) jsonPathExpectedField.value = '';
  }

  if (isHTTPMonitor) {
    if (!httpSchemeField || !httpSkipVerifyField) {
      return;
    }
    if (!isHTTPSEnabled && checkModeField) {
      checkModeField.value = 'http';
    }
    if (httpSkipVerifyLabelField) {
      httpSkipVerifyLabelField.textContent = tr('monitorSkipCert', monitorSkipCertFallback);
    }
    if (String(httpSchemeField.value || 'https').toLowerCase() === 'http') {
      httpSkipVerifyField.checked = false;
      tlsModeField.value = 'none';
    } else {
      tlsModeField.value = httpSkipVerifyField.checked ? 'starttls' : 'tls';
    }
    if (targetField) {
      targetField.placeholder = 'example.com/health';
    }
    if (httpHostField) {
      httpHostField.placeholder = 'example.com oder 2001:db8::1';
    }
    if (httpPortField) {
      httpPortField.placeholder = String(httpSchemeField.value || 'https').toLowerCase() === 'http' ? '80' : '443';
    }
    if (httpPathField) {
      httpPathField.placeholder = '/health';
    }
    if (targetHintField) {
      targetHintField.textContent = String(httpSchemeField.value || 'https').toLowerCase() === 'http'
        ? tr('monitorHintHTTP', 'For HTTP: host/path without protocol (http:// is added automatically).')
        : tr('monitorHintHTTPS', 'For HTTPS: host/path without protocol (https:// is added automatically).');
    }
    if (expectedTextLabelField) {
      expectedTextLabelField.textContent = tr('expectedKeywordsOptional', expectedKeywordsOptionalFallback);
    }
    if (expectedTextHintField) {
      expectedTextHintField.textContent = tr('expectedKeywordsHint', expectedKeywordsHintFallback);
    }
    syncHTTPSFamilyMode();
  } else if (isTCPMonitor) {
    if (useHTTPSLabelField) {
      useHTTPSLabelField.textContent = tr('monitorTCPHandshake', monitorTCPHandshakeFallback);
    }
    if (verifyCertLabelField) {
      verifyCertLabelField.textContent = tr('monitorVerifyCert', monitorVerifyCertFallback);
    }
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (!useHTTPSField.checked) {
      verifyCertField.checked = false;
      tlsModeField.value = 'none';
    } else {
      tlsModeField.value = verifyCertField.checked ? 'tls' : 'starttls';
    }
    if (targetField) {
      targetField.placeholder = 'example.com:443';
    }
    if (tcpHostField) {
      tcpHostField.placeholder = 'example.com oder 2001:db8::1';
    }
    if (tcpPortField) {
      tcpPortField.placeholder = '443';
    }
    if (targetHintField) {
      targetHintField.textContent = '';
    }
    syncTCPFamilyMode();
  } else if (isMail) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    if (mailVerifyLabelField) {
      mailVerifyLabelField.textContent = tr('monitorSkipCert', monitorSkipCertFallback);
    }
    if (tlsModeField.value !== 'none' && tlsModeField.value !== 'tls' && tlsModeField.value !== 'starttls') {
      tlsModeField.value = kind === 'smtp' ? 'starttls' : 'tls';
    }
    if (!mailEncryptionEnabled && mailVerifyField) {
      mailVerifyField.checked = false;
    }
    if (targetField) {
      targetField.placeholder = '';
    }
    if (mailPortField) {
      mailPortField.placeholder = kind === 'smtp' ? '587' : '993';
    }
    if (targetHintField) {
      targetHintField.textContent = '';
    }
    syncMailFamilyMode();
  } else if (isDNS) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    tlsModeField.value = 'none';
    expectedStatusField.value = '';
    if (targetField) {
      targetField.placeholder = 'example.com';
    }
    if (dnsHostField) {
      dnsHostField.placeholder = 'example.com';
    }
    if (dnsRecordTypeField && !dnsRecordTypeField.value) {
      dnsRecordTypeField.value = 'mixed';
    }
    if (dnsServerField) {
      dnsServerField.placeholder = '1.1.1.1 oder 2606:4700:4700::1111';
    }
    if (targetHintField) {
      targetHintField.textContent = tr('monitorHintDNS', 'Hostname to resolve (e.g. example.com).');
    }
    if (expectedTextField) {
      expectedTextField.placeholder = tr('monitorDNSExpectedPlaceholder', '1.2.3.4, 2606:4700:4700::1111');
    }
    if (expectedTextLabelField) {
      expectedTextLabelField.textContent = tr('dnsExpectedOptional', 'Expected DNS keywords (optional)');
    }
    if (expectedTextHintField) {
      expectedTextHintField.textContent = tr('dnsExpectedHint', 'Comma-separated keywords. All keywords must appear in the resolved DNS records.');
    }
  } else if (isSDNS) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    tlsModeField.value = 'none';
    expectedStatusField.value = '';
    const transport = normalizeSDNSTransport(sdnsTransportField?.value);
    if (sdnsTransportField && !sdnsTransportField.value) {
      sdnsTransportField.value = 'doh';
    }
    if (sdnsMethodField && !sdnsMethodField.value) {
      sdnsMethodField.value = 'post';
    }
    if (sdnsRecordTypeField && !sdnsRecordTypeField.value) {
      sdnsRecordTypeField.value = 'mixed';
    }
    if (sdnsMethodRow) {
      sdnsMethodRow.hidden = !sdnsUsesHTTP(transport);
    }
    if (sdnsEndpointField) {
      const placeholder = sdnsEndpointField.dataset[`placeholder${transport === 'doh3' ? 'Doh3' : transport.charAt(0).toUpperCase() + transport.slice(1)}`]
        || sdnsEndpointField.dataset.placeholderDoh
        || '';
      if (placeholder) {
        sdnsEndpointField.placeholder = placeholder;
      }
    }
    if (sdnsEndpointHint) {
      const hint = sdnsEndpointHint.dataset[`hint${transport === 'doh3' ? 'Doh3' : transport.charAt(0).toUpperCase() + transport.slice(1)}`]
        || sdnsEndpointHint.dataset.hintDoh
        || '';
      if (hint) {
        sdnsEndpointHint.textContent = hint;
      }
    }
    if (expectedTextField) {
      expectedTextField.placeholder = tr('monitorDNSExpectedPlaceholder', '1.2.3.4, 2606:4700:4700::1111');
    }
    if (expectedTextLabelField) {
      expectedTextLabelField.textContent = tr('dnsExpectedOptional', 'Expected DNS keywords (optional)');
    }
    if (expectedTextHintField) {
      expectedTextHintField.textContent = tr('dnsExpectedHint', 'Comma-separated keywords. All keywords must appear in the resolved DNS records.');
    }
    syncSDNSFamilyMode();
  } else if (isUDP) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    tlsModeField.value = 'none';
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (targetField) {
      targetField.placeholder = 'example.com:53';
    }
    if (udpHostField) {
      udpHostField.placeholder = 'resolver.example.com oder 2001:db8::1';
    }
    if (udpCheckField && !udpCheckField.value) {
      udpCheckField.value = 'dns';
    }
    syncUDPPortSuggestion();
    if (targetHintField) {
      targetHintField.textContent = tr('monitorHintUDP', 'For UDP: IP/hostname + port (DNS 53, NTP 123).');
    }
    syncUDPFamilyMode();
  } else if (isWhois) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    tlsModeField.value = 'none';
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (targetField) {
      targetField.placeholder = 'example.com';
    }
    if (targetHintField) {
      targetHintField.textContent = '';
    }
  } else if (isPrometheus) {
    if (httpSchemeField) {
      httpSchemeField.value = 'http';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    expectedStatusField.value = '';
    expectedTextField.value = '';
    // Default Prometheus scrapes are plain HTTP; keep explicit tls/starttls when editing.
    if (tlsModeField.value !== 'tls' && tlsModeField.value !== 'starttls' && tlsModeField.value !== 'none') {
      tlsModeField.value = 'none';
    }
    if (String(targetField?.value || '').toLowerCase().startsWith('http://')) {
      tlsModeField.value = 'none';
    } else if (String(targetField?.value || '').toLowerCase().startsWith('https://')) {
      if (tlsModeField.value === 'none') {
        tlsModeField.value = 'tls';
      }
    } else if (!targetField?.value) {
      tlsModeField.value = 'none';
    }
    if (promComparisonField && !promComparisonField.value) {
      promComparisonField.value = 'eq';
    }
    if (targetField) {
      targetField.placeholder = 'http://prometheus:9090';
      targetField.required = true;
    }
    if (targetHintField) {
      targetHintField.textContent = tr('monitorHintPrometheus', 'Prometheus base URL (e.g. http://prometheus:9090).');
    }
  } else if (isGRPC) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (useHTTPSLabelField) {
      useHTTPSLabelField.textContent = tr('monitorTCPHandshake', monitorTCPHandshakeFallback);
    }
    if (verifyCertLabelField) {
      verifyCertLabelField.textContent = tr('monitorVerifyCert', monitorVerifyCertFallback);
    }
    if (!useHTTPSField.checked) {
      verifyCertField.checked = false;
      tlsModeField.value = 'none';
    } else {
      tlsModeField.value = verifyCertField.checked ? 'tls' : 'starttls';
    }
    if (tcpHostField) {
      tcpHostField.placeholder = 'grpc.example.com oder 2001:db8::1';
    }
    if (tcpPortField) {
      tcpPortField.placeholder = '443';
    }
    if (targetHintField) {
      targetHintField.textContent = tr('monitorHintGRPC', 'gRPC host:port for the health service.');
    }
    syncTCPFamilyMode();
  } else if (isICMPMonitor) {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (targetField) {
      targetField.placeholder = '1.1.1.1 oder host.example.com';
    }
    if (targetHintField) {
      targetHintField.textContent = '';
    }
    syncICMPFamilyMode();
  } else {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
    tlsModeField.value = 'none';
    expectedStatusField.value = '';
    expectedTextField.value = '';
    if (kind === 'tcp') {
      if (targetField) {
        targetField.placeholder = 'example.com:443';
      }
      if (targetHintField) {
        targetHintField.textContent = '';
      }
    } else if (kind === 'icmp') {
      if (targetField) {
        targetField.placeholder = '1.1.1.1';
      }
      if (targetHintField) {
        targetHintField.textContent = '';
      }
    }
  }

  if (!isICMPMonitor && icmpFamilyRow) {
    icmpFamilyRow.hidden = true;
  }
  if (!(isTCPMonitor || isGRPC) && tcpFamilyRow) {
    tcpFamilyRow.hidden = true;
  }
  if (!isPrometheus && promQueryField) {
    promQueryField.required = false;
  }
  if (!isDNS && dnsTargetRow) {
    dnsTargetRow.hidden = true;
  }
  if (!isSDNS && sdnsTargetRow) {
    sdnsTargetRow.hidden = true;
  }
  if (!isSDNS && sdnsFamilyRow) {
    sdnsFamilyRow.hidden = true;
  }
  if (!isMail && mailFamilyRow) {
    mailFamilyRow.hidden = true;
  }
  if (!isMail && mailVerifyRow) {
    mailVerifyRow.hidden = true;
  }
  if (!isHTTPMonitor && httpsFamilyRow) {
    httpsFamilyRow.hidden = true;
  }
  if (!isUDP && udpFamilyRow) {
    udpFamilyRow.hidden = true;
  }

  syncWhoisTargetDisclaimer();
  syncHeartbeatRows(isHeartbeat);
};
