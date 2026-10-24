import {
  cancelButton, dialog, dnsHostField, dnsRecordTypeField, dnsServerField, httpHostField,
  httpPathField, httpPortField, httpSchemeField, httpSkipVerifyField, httpsFamilyField,
  icmpFamilyField, kindField, mailFamilyField, mailHostField, mailPortField, mailVerifyField,
  monitorCloseButton, monitorForm, openCreateButton, targetField, tcpFamilyField, tcpHostField,
  tcpPortField, tlsModeField, udpCheckField, udpFamilyField, udpHostField, udpPortField,
  useHTTPSField, verifyCertField
} from './dom.js';
import { initHeartbeatForm } from './monitor-heartbeat.js';
import { openCreate } from './monitor-dialog.js';
import { applyKindRules } from './monitor-kind-rules.js';
import {
  composeDNSTarget, composeHTTPSMonitorTarget, defaultUDPPortForCheck, formatHostPort, isLiteralIP,
  normalizeUDPCheck
} from './monitor-target.js';

export function initMonitorForm() {
  initHeartbeatForm();
  openCreateButton?.addEventListener('click', openCreate);
  cancelButton?.addEventListener('click', () => dialog?.close());
  monitorCloseButton?.addEventListener('click', () => dialog?.close());

  kindField?.addEventListener('change', applyKindRules);
  tlsModeField?.addEventListener('change', () => {
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      applyKindRules();
    }
  });
  targetField?.addEventListener('input', () => {
    if (kindField?.value === 'icmp' || kindField?.value === 'whois') {
      applyKindRules();
    }
  });
  tcpHostField?.addEventListener('input', () => {
    if (kindField?.value === 'tcp') {
      applyKindRules();
    }
  });
  tcpPortField?.addEventListener('input', () => {
    if (kindField?.value === 'tcp') {
      const value = String(tcpPortField.value || '').trim();
      targetField.value = formatHostPort(tcpHostField?.value, value);
    }
  });
  tcpFamilyField?.addEventListener('change', () => {
    if (kindField?.value === 'tcp') {
      applyKindRules();
    }
  });
  dnsHostField?.addEventListener('input', () => {
    if (kindField?.value === 'dns' && targetField) {
      targetField.value = composeDNSTarget();
    }
  });
  dnsRecordTypeField?.addEventListener('change', () => {
    if (kindField?.value === 'dns' && targetField) {
      targetField.value = composeDNSTarget();
    }
  });
  dnsServerField?.addEventListener('input', () => {
    if (kindField?.value === 'dns' && targetField) {
      targetField.value = composeDNSTarget();
    }
  });
  mailHostField?.addEventListener('input', () => {
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      targetField.value = formatHostPort(mailHostField?.value, mailPortField?.value);
      applyKindRules();
    }
  });
  mailPortField?.addEventListener('input', () => {
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      targetField.value = formatHostPort(mailHostField?.value, mailPortField?.value);
    }
  });
  mailFamilyField?.addEventListener('change', () => {
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      applyKindRules();
    }
  });
  mailVerifyField?.addEventListener('change', () => {
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      applyKindRules();
    }
  });
  udpCheckField?.addEventListener('change', () => {
    if (kindField?.value === 'udp') {
      if (udpPortField && !String(udpPortField.value || '').trim()) {
        udpPortField.value = defaultUDPPortForCheck(udpCheckField.value);
      }
      applyKindRules();
    }
  });
  udpHostField?.addEventListener('input', () => {
    if (kindField?.value === 'udp') {
      applyKindRules();
    }
  });
  udpPortField?.addEventListener('input', () => {
    if (kindField?.value === 'udp') {
      targetField.value = formatHostPort(udpHostField?.value, udpPortField?.value);
    }
  });
  udpFamilyField?.addEventListener('change', () => {
    if (kindField?.value === 'udp') {
      applyKindRules();
    }
  });
  httpHostField?.addEventListener('input', () => {
    if (kindField?.value === 'https') {
      applyKindRules();
    }
  });
  httpSchemeField?.addEventListener('change', () => {
    if (kindField?.value === 'https') {
      applyKindRules();
      targetField.value = composeHTTPSMonitorTarget();
    }
  });
  httpPortField?.addEventListener('input', () => {
    if (kindField?.value === 'https') {
      targetField.value = composeHTTPSMonitorTarget();
    }
  });
  httpPathField?.addEventListener('input', () => {
    if (kindField?.value === 'https') {
      targetField.value = composeHTTPSMonitorTarget();
    }
  });
  httpSkipVerifyField?.addEventListener('change', () => {
    if (kindField?.value === 'https') {
      applyKindRules();
    }
  });
  httpsFamilyField?.addEventListener('change', () => {
    if (kindField?.value === 'https') {
      applyKindRules();
    }
  });
  icmpFamilyField?.addEventListener('change', () => {
    if (kindField?.value === 'icmp') {
      applyKindRules();
    }
  });
  monitorForm?.addEventListener('submit', (event) => {
    if (kindField?.value === 'dns') {
      const normalizedTarget = composeDNSTarget();
      if (!normalizedTarget) {
        event.preventDefault();
        return;
      }
      if (targetField) {
        targetField.value = normalizedTarget;
      }
      return;
    }
    if (kindField?.value === 'https') {
      const normalizedTarget = composeHTTPSMonitorTarget();
      if (!normalizedTarget) {
        event.preventDefault();
        return;
      }
      if (targetField) {
        targetField.value = normalizedTarget;
      }
      if (httpsFamilyField) {
        const host = String(httpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
        if (!host || isLiteralIP(host)) {
          httpsFamilyField.value = 'dual';
        }
      }
      return;
    }
    if (kindField?.value === 'udp') {
      const normalizedTarget = formatHostPort(udpHostField?.value, udpPortField?.value);
      if (!normalizedTarget) {
        event.preventDefault();
        return;
      }
      if (targetField) {
        targetField.value = normalizedTarget;
      }
      if (udpFamilyField) {
        const host = String(udpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
        if (!host || isLiteralIP(host)) {
          udpFamilyField.value = 'dual';
        }
      }
      if (udpCheckField) {
        udpCheckField.value = normalizeUDPCheck(udpCheckField.value);
      }
      return;
    }
    if (kindField?.value === 'smtp' || kindField?.value === 'imap') {
      const normalizedTarget = formatHostPort(mailHostField?.value, mailPortField?.value);
      if (!normalizedTarget) {
        event.preventDefault();
        return;
      }
      if (targetField) {
        targetField.value = normalizedTarget;
      }
      if (mailFamilyField) {
        const host = String(mailHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
        if (!host || isLiteralIP(host)) {
          mailFamilyField.value = 'dual';
        }
      }
      return;
    }
    if (kindField?.value !== 'tcp') {
      return;
    }
    const normalizedTarget = formatHostPort(tcpHostField?.value, tcpPortField?.value);
    if (!normalizedTarget) {
      event.preventDefault();
      return;
    }
    if (targetField) {
      targetField.value = normalizedTarget;
    }
    if (tcpFamilyField) {
      const host = String(tcpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
      if (!host || isLiteralIP(host)) {
        tcpFamilyField.value = 'dual';
      }
    }
  });
  useHTTPSField?.addEventListener('change', applyKindRules);
  verifyCertField?.addEventListener('change', applyKindRules);
}
