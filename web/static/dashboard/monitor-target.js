import {
  dnsHostField, dnsRecordTypeField, dnsServerField, httpHostField, httpPathField, httpPortField,
  httpSchemeField
} from './dom.js';

export const isLiteralIP = (value) => {
  const text = String(value || '').trim();
  if (!text) {
    return false;
  }
  const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4Pattern.test(text)) {
    return true;
  }
  if (text.includes(':')) {
    const compact = text.replace(/^\[/, '').replace(/\]$/, '');
    const ipv6Pattern = /^[0-9a-fA-F:]+$/;
    return ipv6Pattern.test(compact);
  }
  return false;
};

export const parseHostPort = (value) => {
  const text = String(value || '').trim();
  if (!text) {
    return { host: '', port: '' };
  }
  if (text.startsWith('[')) {
    const closeIndex = text.indexOf(']');
    if (closeIndex > 0) {
      const host = text.slice(1, closeIndex).trim();
      const rest = text.slice(closeIndex + 1);
      if (rest.startsWith(':')) {
        return { host, port: rest.slice(1).trim() };
      }
    }
  }
  const firstColon = text.indexOf(':');
  const lastColon = text.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) {
    return { host: text.slice(0, firstColon).trim(), port: text.slice(firstColon + 1).trim() };
  }
  return { host: text, port: '' };
};

export const formatHostPort = (hostValue, portValue) => {
  const host = String(hostValue || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const port = String(portValue || '').trim();
  if (!host || !port) {
    return '';
  }
  const normalizedHost = host.includes(':') ? `[${host}]` : host;
  return `${normalizedHost}:${port}`;
};

export const normalizeDNSRecordType = (value) => {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'a' || raw === 'aaaa' || raw === 'cname' || raw === 'mx' || raw === 'txt' || raw === 'ns' || raw === 'srv' || raw === 'caa' || raw === 'soa') {
    return raw;
  }
  return 'mixed';
};

export const parseDNSTarget = (value) => {
  const raw = String(value || '').trim();
  if (!raw) {
    return { host: '', recordType: 'mixed', server: '' };
  }
  const parts = raw.split('|');
  if (parts.length === 1) {
    return { host: raw, recordType: 'mixed', server: '' };
  }
  return {
    host: String(parts[0] || '').trim(),
    recordType: normalizeDNSRecordType(parts[1]),
    server: String(parts.slice(2).join('|') || '').trim()
  };
};

export const composeDNSTarget = () => {
  const host = String(dnsHostField?.value || '').trim();
  if (!host) {
    return '';
  }
  const recordType = normalizeDNSRecordType(dnsRecordTypeField?.value);
  const server = String(dnsServerField?.value || '').trim();
  if (recordType === 'mixed' && !server) {
    return host;
  }
  return `${host}|${recordType}|${server}`;
};

export const parseHTTPURLTarget = (value) => {
  const raw = String(value || '').trim();
  if (!raw) {
    return { scheme: 'https', host: '', port: '', path: '' };
  }
  try {
    const parsed = new URL(raw);
    const protocol = String(parsed.protocol || '').toLowerCase();
    const scheme = protocol === 'http:' ? 'http' : 'https';
    return {
      scheme,
      host: String(parsed.hostname || '').trim(),
      port: String(parsed.port || '').trim(),
      path: `${parsed.pathname || ''}${parsed.search || ''}`
    };
  } catch (_) {
    return { scheme: 'https', host: '', port: '', path: '' };
  }
};

const formatHTTPHostPort = (hostValue, portValue) => {
  const host = String(hostValue || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  const port = String(portValue || '').trim();
  if (!host) {
    return '';
  }
  if (!port) {
    return host;
  }
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
};

export const composeHTTPSMonitorTarget = () => {
  const hostPort = formatHTTPHostPort(httpHostField?.value, httpPortField?.value);
  if (!hostPort) {
    return '';
  }
  let path = String(httpPathField?.value || '').trim();
  if (path && !path.startsWith('/') && !path.startsWith('?')) {
    path = `/${path}`;
  }
  const scheme = String(httpSchemeField?.value || 'https').toLowerCase() === 'http' ? 'http://' : 'https://';
  return `${scheme}${hostPort}${path}`;
};

export const normalizeUDPCheck = (value) => {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'dns' || raw === 'ntp') {
    return raw;
  }
  return 'dns';
};

export const defaultUDPPortForCheck = (check) => {
  switch (normalizeUDPCheck(check)) {
    case 'ntp':
      return '123';
    default:
      return '53';
  }
};
