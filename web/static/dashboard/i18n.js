import {
  expectedTextHintField, expectedTextLabelField, httpSkipVerifyLabelField, title,
  useHTTPSLabelField, verifyCertLabelField
} from './dom.js';

const i18n = (() => {
  // Translations ship as a JSON data block: the CSP (script-src 'self') blocks inline scripts.
  try {
    return JSON.parse(document.getElementById('goup-dashboard-i18n')?.textContent || '{}');
  } catch (_) {
    return {};
  }
})();
export const monitorCreateTitleFallback = String(title?.dataset?.createTitle || title?.textContent || 'Create monitor').trim() || 'Create monitor';
export const monitorEditTitleFallback = String(title?.dataset?.editTitle || 'Edit monitor').trim() || 'Edit monitor';
export const monitorSkipCertFallback = String(httpSkipVerifyLabelField?.textContent || 'Do not verify certificate').trim() || 'Do not verify certificate';
export const monitorTCPHandshakeFallback = String(useHTTPSLabelField?.textContent || 'Check TLS handshake').trim() || 'Check TLS handshake';
export const monitorVerifyCertFallback = String(verifyCertLabelField?.textContent || 'Verify certificate').trim() || 'Verify certificate';
export const expectedKeywordsOptionalFallback = String(expectedTextLabelField?.textContent || 'Expected keywords (optional)').trim() || 'Expected keywords (optional)';
export const expectedKeywordsHintFallback = String(expectedTextHintField?.textContent || 'Separate multiple keywords with commas. All keywords must appear in the body.').trim() || 'Separate multiple keywords with commas. All keywords must appear in the body.';
export const entriesLabelFallback = String(document.querySelector('#dashboard-live-state-events summary .muted')?.textContent || '')
  .replace(/[0-9]+/g, '')
  .trim() || 'entries';
export const tr = (key, fallback, values = {}) => {
  let text = (typeof i18n[key] === 'string' && i18n[key].trim() !== '') ? i18n[key] : fallback;
  Object.entries(values).forEach(([name, value]) => {
    text = text.replaceAll(`{${name}}`, String(value ?? ''));
  });
  return text;
};
