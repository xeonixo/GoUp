import {
  dialog, dnsHostField, dnsRecordTypeField, dnsServerField, enabledField, expectedStatusField,
  expectedTextField, groupField, httpHostField, httpPathField, httpPortField, httpSchemeField,
  httpSkipVerifyField, httpsFamilyField, icmpFamilyField, idField, intervalField, kindField,
  mailFamilyField, mailHostField, mailPortField, mailVerifyField, monitorExecutorField, nameField,
  notifyField, retryCountField, retryIntervalField, sdnsEndpointField, sdnsFamilyField, sdnsHostField,
  sdnsMethodField, sdnsRecordTypeField, sdnsSNIField, sdnsSkipCertField, sdnsTransportField, targetField,
  tcpFamilyField, tcpHostField, tcpPortField, timeoutField, title, tlsModeField, udpCheckField,
  udpFamilyField, udpHostField, udpPortField, useHTTPSField, verifyCertField
} from './dom.js';
import { monitorCreateTitleFallback, monitorEditTitleFallback, tr } from './i18n.js';
import { fillHeartbeat, resetHeartbeat } from './monitor-heartbeat.js';
import { applyKindRules } from './monitor-kind-rules.js';
import {
  defaultUDPPortForCheck, normalizeDNSRecordType, normalizeUDPCheck, parseDNSTarget,
  parseHTTPURLTarget, parseHostPort, parseSDNSMode, parseSDNSTarget
} from './monitor-target.js';

export const openCreate = () => {
  if (!title || !idField || !nameField || !groupField || !kindField || !tlsModeField || !targetField || !intervalField || !timeoutField || !expectedStatusField || !expectedTextField || !enabledField || !notifyField || !dialog) {
    return;
  }
  title.textContent = tr('monitorCreateTitle', monitorCreateTitleFallback);
  idField.value = '';
  nameField.value = '';
  groupField.value = '';
  kindField.value = 'https';
  if (monitorExecutorField) {
    monitorExecutorField.value = 'local';
  }
  tlsModeField.value = 'tls';
  if (icmpFamilyField) {
    icmpFamilyField.value = 'ipv4';
  }
  if (httpsFamilyField) {
    httpsFamilyField.value = 'dual';
  }
  if (tcpFamilyField) {
    tcpFamilyField.value = 'dual';
  }
  if (mailFamilyField) {
    mailFamilyField.value = 'dual';
  }
  if (udpFamilyField) {
    udpFamilyField.value = 'dual';
  }
  if (udpCheckField) {
    udpCheckField.value = 'dns';
  }
  targetField.value = '';
  if (httpHostField) {
    httpHostField.value = '';
  }
  if (httpSchemeField) {
    httpSchemeField.value = 'https';
  }
  if (httpPortField) {
    httpPortField.value = '';
  }
  if (httpPathField) {
    httpPathField.value = '';
  }
  if (httpSkipVerifyField) {
    httpSkipVerifyField.checked = false;
  }
  if (tcpHostField) {
    tcpHostField.value = '';
  }
  if (tcpPortField) {
    tcpPortField.value = '';
  }
  if (dnsHostField) {
    dnsHostField.value = '';
  }
  if (dnsRecordTypeField) {
    dnsRecordTypeField.value = 'mixed';
  }
  if (dnsServerField) {
    dnsServerField.value = '';
  }
  if (sdnsHostField) {
    sdnsHostField.value = '';
  }
  if (sdnsRecordTypeField) {
    sdnsRecordTypeField.value = 'mixed';
  }
  if (sdnsTransportField) {
    sdnsTransportField.value = 'doh';
  }
  if (sdnsMethodField) {
    sdnsMethodField.value = 'post';
  }
  if (sdnsEndpointField) {
    sdnsEndpointField.value = '';
  }
  if (sdnsSNIField) {
    sdnsSNIField.value = '';
  }
  if (sdnsSkipCertField) {
    sdnsSkipCertField.checked = false;
  }
  if (sdnsFamilyField) {
    sdnsFamilyField.value = 'dual';
  }
  if (mailHostField) {
    mailHostField.value = '';
  }
  if (mailPortField) {
    mailPortField.value = '';
  }
  if (mailVerifyField) {
    mailVerifyField.checked = false;
  }
  if (udpHostField) {
    udpHostField.value = '';
  }
  if (udpPortField) {
    udpPortField.value = defaultUDPPortForCheck('dns');
  }
  intervalField.value = '60';
  timeoutField.value = '10';
  expectedStatusField.value = '';
  expectedTextField.value = '';
  useHTTPSField.checked = true;
  verifyCertField.checked = true;
  enabledField.checked = true;
  notifyField.checked = true;
  if (retryCountField) retryCountField.value = '0';
  if (retryIntervalField) retryIntervalField.value = '0';
  resetHeartbeat();
  applyKindRules();
  dialog.showModal();
};

export const openEdit = (button) => {
  if (!title || !idField || !nameField || !groupField || !kindField || !tlsModeField || !targetField || !intervalField || !timeoutField || !expectedStatusField || !expectedTextField || !enabledField || !notifyField || !dialog) {
    return;
  }
  title.textContent = tr('monitorEditTitle', monitorEditTitleFallback);
  idField.value = button.dataset.id || '';
  nameField.value = button.dataset.name || '';
  groupField.value = button.dataset.group || '';
  kindField.value = button.dataset.kind || 'https';
  if (monitorExecutorField) {
    monitorExecutorField.value = button.dataset.executor || 'local';
  }
  const rawTLSMode = String(button.dataset.tlsMode || 'tls').toLowerCase();
  const baseTLSMode = rawTLSMode.endsWith('_ipv4') || rawTLSMode.endsWith('_ipv6') || rawTLSMode.endsWith('_dual')
    ? rawTLSMode.replace(/_(ipv4|ipv6|dual)$/, '')
    : rawTLSMode;
  tlsModeField.value = baseTLSMode;
  if (icmpFamilyField) {
    if (tlsModeField.value === 'starttls') {
      icmpFamilyField.value = 'ipv6';
    } else if (tlsModeField.value === 'none') {
      icmpFamilyField.value = 'dual';
    } else {
      icmpFamilyField.value = 'ipv4';
    }
  }
  const rawTarget = button.dataset.target || '';
  targetField.value = rawTarget;
  const monitorKind = button.dataset.kind || 'https';
  if (monitorKind === 'https') {
    const httpsModeRaw = String(button.dataset.tlsMode || 'tls').toLowerCase();
    if (httpSchemeField) {
      if (httpsModeRaw === 'none' || httpsModeRaw.startsWith('none_')) {
        httpSchemeField.value = 'http';
      } else {
        httpSchemeField.value = 'https';
      }
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = httpsModeRaw === 'starttls' || httpsModeRaw.startsWith('starttls_');
    }
    if (httpsFamilyField) {
      if (httpsModeRaw.endsWith('_ipv6')) {
        httpsFamilyField.value = 'ipv6';
      } else if (httpsModeRaw.endsWith('_ipv4')) {
        httpsFamilyField.value = 'ipv4';
      } else {
        httpsFamilyField.value = 'dual';
      }
    }
    const parsedHTTP = parseHTTPURLTarget(rawTarget);
    if (httpSchemeField) {
      httpSchemeField.value = parsedHTTP.scheme;
    }
    if (httpHostField) {
      httpHostField.value = parsedHTTP.host;
    }
    if (httpPortField) {
      httpPortField.value = parsedHTTP.port;
    }
    if (httpPathField) {
      httpPathField.value = parsedHTTP.path;
    }
  } else {
    if (httpSchemeField) {
      httpSchemeField.value = 'https';
    }
    if (httpSkipVerifyField) {
      httpSkipVerifyField.checked = false;
    }
    if (httpHostField) {
      httpHostField.value = '';
    }
    if (httpPortField) {
      httpPortField.value = '';
    }
    if (httpPathField) {
      httpPathField.value = '';
    }
    if (httpsFamilyField) {
      httpsFamilyField.value = 'dual';
    }
  }
  if (monitorKind === 'tcp') {
    const tcpModeRaw = String(button.dataset.tlsMode || 'none').toLowerCase();
    if (tcpFamilyField) {
      if (tcpModeRaw.endsWith('_ipv6')) {
        tcpFamilyField.value = 'ipv6';
      } else if (tcpModeRaw.endsWith('_ipv4')) {
        tcpFamilyField.value = 'ipv4';
      } else {
        tcpFamilyField.value = 'dual';
      }
    }
    const parsedTarget = parseHostPort(rawTarget);
    if (tcpHostField) {
      tcpHostField.value = parsedTarget.host;
    }
    if (tcpPortField) {
      tcpPortField.value = parsedTarget.port;
    }
  } else {
    if (tcpHostField) {
      tcpHostField.value = '';
    }
    if (tcpPortField) {
      tcpPortField.value = '';
    }
    if (tcpFamilyField) {
      tcpFamilyField.value = 'dual';
    }
  }
  if (monitorKind === 'dns') {
    const parsedTarget = parseDNSTarget(rawTarget);
    if (dnsHostField) {
      dnsHostField.value = parsedTarget.host;
    }
    if (dnsRecordTypeField) {
      dnsRecordTypeField.value = normalizeDNSRecordType(parsedTarget.recordType);
    }
    if (dnsServerField) {
      dnsServerField.value = parsedTarget.server;
    }
  } else {
    if (dnsHostField) {
      dnsHostField.value = '';
    }
    if (dnsRecordTypeField) {
      dnsRecordTypeField.value = 'mixed';
    }
    if (dnsServerField) {
      dnsServerField.value = '';
    }
  }
  if (monitorKind === 'sdns') {
    const parsedTarget = parseSDNSTarget(rawTarget);
    const parsedMode = parseSDNSMode(button.dataset.tlsMode || 'doh');
    if (sdnsHostField) {
      sdnsHostField.value = parsedTarget.host;
    }
    if (sdnsRecordTypeField) {
      sdnsRecordTypeField.value = normalizeDNSRecordType(parsedTarget.recordType);
    }
    if (sdnsTransportField) {
      sdnsTransportField.value = parsedMode.transport;
    }
    if (sdnsMethodField) {
      sdnsMethodField.value = parsedMode.method;
    }
    if (sdnsEndpointField) {
      sdnsEndpointField.value = parsedTarget.endpoint;
    }
    if (sdnsSNIField) {
      sdnsSNIField.value = parsedTarget.sni;
    }
    if (sdnsSkipCertField) {
      sdnsSkipCertField.checked = parsedMode.skipCert;
    }
    if (sdnsFamilyField) {
      sdnsFamilyField.value = parsedMode.family;
    }
  } else {
    if (sdnsHostField) {
      sdnsHostField.value = '';
    }
    if (sdnsRecordTypeField) {
      sdnsRecordTypeField.value = 'mixed';
    }
    if (sdnsTransportField) {
      sdnsTransportField.value = 'doh';
    }
    if (sdnsMethodField) {
      sdnsMethodField.value = 'post';
    }
    if (sdnsEndpointField) {
      sdnsEndpointField.value = '';
    }
    if (sdnsSNIField) {
      sdnsSNIField.value = '';
    }
    if (sdnsSkipCertField) {
      sdnsSkipCertField.checked = false;
    }
    if (sdnsFamilyField) {
      sdnsFamilyField.value = 'dual';
    }
  }
  if (monitorKind === 'smtp' || monitorKind === 'imap') {
    const mailModeRaw = String(button.dataset.tlsMode || (monitorKind === 'smtp' ? 'starttls' : 'tls')).toLowerCase();
    const mailModeBase = mailModeRaw.endsWith('_ipv4') || mailModeRaw.endsWith('_ipv6') || mailModeRaw.endsWith('_dual')
      ? mailModeRaw.replace(/_(ipv4|ipv6|dual)$/, '')
      : mailModeRaw;
    if (tlsModeField) {
      if (mailModeBase === 'tls_insecure') {
        tlsModeField.value = 'tls';
      } else if (mailModeBase === 'starttls_insecure') {
        tlsModeField.value = 'starttls';
      } else if (mailModeBase === 'none' || mailModeBase === 'tls' || mailModeBase === 'starttls') {
        tlsModeField.value = mailModeBase;
      } else {
        tlsModeField.value = monitorKind === 'smtp' ? 'starttls' : 'tls';
      }
    }
    if (mailVerifyField) {
      mailVerifyField.checked = (mailModeBase === 'tls_insecure' || mailModeBase === 'starttls_insecure');
    }
    if (mailFamilyField) {
      if (mailModeRaw.endsWith('_ipv6')) {
        mailFamilyField.value = 'ipv6';
      } else if (mailModeRaw.endsWith('_ipv4')) {
        mailFamilyField.value = 'ipv4';
      } else {
        mailFamilyField.value = 'dual';
      }
    }
    const parsedTarget = parseHostPort(rawTarget);
    if (mailHostField) {
      mailHostField.value = parsedTarget.host;
    }
    if (mailPortField) {
      mailPortField.value = parsedTarget.port;
    }
  } else {
    if (mailHostField) {
      mailHostField.value = '';
    }
    if (mailPortField) {
      mailPortField.value = '';
    }
    if (mailFamilyField) {
      mailFamilyField.value = 'dual';
    }
    if (mailVerifyField) {
      mailVerifyField.checked = false;
    }
  }
  if (monitorKind === 'udp') {
    const udpModeRaw = String(button.dataset.tlsMode || 'none').toLowerCase();
    const baseUDPMode = udpModeRaw.replace(/_(ipv4|ipv6|dual)$/, '');
    if (udpCheckField) {
      udpCheckField.value = normalizeUDPCheck(baseUDPMode === 'none' ? 'wireguard' : baseUDPMode);
    }
    if (udpFamilyField) {
      if (udpModeRaw.endsWith('_ipv6')) {
        udpFamilyField.value = 'ipv6';
      } else if (udpModeRaw.endsWith('_ipv4')) {
        udpFamilyField.value = 'ipv4';
      } else {
        udpFamilyField.value = 'dual';
      }
    }
    const parsedTarget = parseHostPort(rawTarget);
    if (udpHostField) {
      udpHostField.value = parsedTarget.host;
    }
    if (udpPortField) {
      udpPortField.value = parsedTarget.port || defaultUDPPortForCheck(udpCheckField?.value);
    }
  } else {
    if (udpCheckField) {
      udpCheckField.value = 'dns';
    }
    if (udpHostField) {
      udpHostField.value = '';
    }
    if (udpPortField) {
      udpPortField.value = defaultUDPPortForCheck('dns');
    }
    if (udpFamilyField) {
      udpFamilyField.value = 'dual';
    }
  }
  intervalField.value = button.dataset.interval || '60';
  timeoutField.value = button.dataset.timeout || '10';
  expectedStatusField.value = button.dataset.expectedStatus || '';
  expectedTextField.value = button.dataset.expectedText || '';
  const tlsModeRaw = String(button.dataset.tlsMode || 'tls').toLowerCase();
  const tlsMode = tlsModeRaw.endsWith('_ipv4') || tlsModeRaw.endsWith('_ipv6') || tlsModeRaw.endsWith('_dual')
    ? tlsModeRaw.replace(/_(ipv4|ipv6|dual)$/, '')
    : tlsModeRaw;
  if (tlsMode === 'none') {
    useHTTPSField.checked = false;
    verifyCertField.checked = false;
  } else if (tlsMode === 'starttls') {
    useHTTPSField.checked = true;
    verifyCertField.checked = false;
  } else {
    useHTTPSField.checked = true;
    verifyCertField.checked = true;
  }
  enabledField.checked = button.dataset.enabled === '1';
  notifyField.checked = button.dataset.notifyOnRecovery === '1';
  if (retryCountField) retryCountField.value = button.dataset.retryCount || '0';
  if (retryIntervalField) retryIntervalField.value = button.dataset.retryInterval || '0';
  fillHeartbeat(button);
  applyKindRules();
  dialog.showModal();
};
