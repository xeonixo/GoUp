// Per-kind helpers for the monitor form; they only run after applyKindRules() verified its required fields.

import {
  httpHostField, httpsFamilyField, httpsFamilyRow, icmpFamilyField, icmpFamilyRow, kindField,
  mailFamilyField, mailFamilyRow, mailHostField, sdnsEndpointField, sdnsFamilyField, sdnsFamilyRow,
  sdnsTransportField, targetField, targetWarnField, tcpFamilyField,
  tcpFamilyRow, tcpHostField, tlsModeField, udpCheckField, udpFamilyField, udpFamilyRow,
  udpHostField, udpPortField
} from './dom.js';
import { defaultUDPPortForCheck, isLiteralIP, sdnsEndpointHost } from './monitor-target.js';

export const syncICMPFamilyMode = () => {
  if (!icmpFamilyRow || !icmpFamilyField) {
    return;
  }
  const isICMPMonitor = kindField.value === 'icmp';
  if (!isICMPMonitor) {
    icmpFamilyRow.hidden = true;
    return;
  }

  const targetValue = String(targetField?.value || '').trim();
  const requiresFamily = targetValue !== '' && !isLiteralIP(targetValue);
  icmpFamilyRow.hidden = !requiresFamily;

  if (!requiresFamily) {
    tlsModeField.value = 'none';
    return;
  }

  const selectedFamily = String(icmpFamilyField.value || 'ipv4').toLowerCase();
  if (selectedFamily === 'ipv6') {
    tlsModeField.value = 'starttls';
  } else if (selectedFamily === 'dual') {
    tlsModeField.value = 'none';
  } else {
    tlsModeField.value = 'tls';
  }
};

export const syncTCPFamilyMode = () => {
  if (!tcpFamilyRow || !tcpFamilyField) {
    return;
  }
  const isTCPMonitor = kindField.value === 'tcp';
  if (!isTCPMonitor) {
    tcpFamilyRow.hidden = true;
    return;
  }

  const tcpHost = String(tcpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const requiresFamily = tcpHost !== '' && !isLiteralIP(tcpHost);
  tcpFamilyRow.hidden = !requiresFamily;
  if (!requiresFamily) {
    tcpFamilyField.value = 'dual';
  }
};

export const syncMailFamilyMode = () => {
  if (!mailFamilyRow || !mailFamilyField) {
    return;
  }
  const isMailMonitor = kindField.value === 'smtp' || kindField.value === 'imap';
  if (!isMailMonitor) {
    mailFamilyRow.hidden = true;
    return;
  }

  const mailHost = String(mailHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const requiresFamily = mailHost !== '' && !isLiteralIP(mailHost);
  mailFamilyRow.hidden = !requiresFamily;
  if (!requiresFamily) {
    mailFamilyField.value = 'dual';
  }
};

export const syncUDPFamilyMode = () => {
  if (!udpFamilyRow || !udpFamilyField) {
    return;
  }
  const isUDPMonitor = kindField.value === 'udp';
  if (!isUDPMonitor) {
    udpFamilyRow.hidden = true;
    return;
  }

  const udpHost = String(udpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const requiresFamily = udpHost !== '' && !isLiteralIP(udpHost);
  udpFamilyRow.hidden = !requiresFamily;
  if (!requiresFamily) {
    udpFamilyField.value = 'dual';
  }
};

export const syncUDPPortSuggestion = () => {
  if (!udpPortField) {
    return;
  }
  const suggestedPort = defaultUDPPortForCheck(udpCheckField?.value);
  udpPortField.placeholder = suggestedPort;
  if (!String(udpPortField.value || '').trim()) {
    udpPortField.value = suggestedPort;
  }
};

export const syncSDNSFamilyMode = () => {
  if (!sdnsFamilyRow || !sdnsFamilyField) {
    return;
  }
  const isSDNSMonitor = kindField?.value === 'sdns';
  if (!isSDNSMonitor) {
    sdnsFamilyRow.hidden = true;
    return;
  }
  const host = sdnsEndpointHost(sdnsTransportField?.value, sdnsEndpointField?.value);
  const requiresFamily = host !== '' && !isLiteralIP(host);
  sdnsFamilyRow.hidden = !requiresFamily;
  if (!requiresFamily) {
    sdnsFamilyField.value = 'dual';
  }
};

export const syncHTTPSFamilyMode = () => {
  if (!httpsFamilyRow || !httpsFamilyField) {
    return;
  }
  const isHTTPMonitor = kindField.value === 'https';
  if (!isHTTPMonitor) {
    httpsFamilyRow.hidden = true;
    return;
  }

  const httpHost = String(httpHostField?.value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const requiresFamily = httpHost !== '' && !isLiteralIP(httpHost);
  httpsFamilyRow.hidden = !requiresFamily;
  if (!requiresFamily) {
    httpsFamilyField.value = 'dual';
  }
};

const isDEWhoisTarget = (value) => {
  const domain = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  return domain.length > 3 && domain.endsWith('.de');
};

export const syncWhoisTargetDisclaimer = () => {
  if (!targetWarnField) {
    return;
  }
  const isWhoisMonitor = kindField?.value === 'whois';
  targetWarnField.hidden = !(isWhoisMonitor && isDEWhoisTarget(targetField?.value));
};
