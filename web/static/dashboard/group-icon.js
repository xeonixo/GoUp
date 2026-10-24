import { appBase } from './config.js';
import { bindDialogBackdropClose } from './dom-utils.js';
import {
  groupCancelButton, groupDialog, groupForm, groupIconConsentConfirm, groupIconConsentPanel,
  groupIconPreview, groupIconPreviewFrame, groupIconRemoteConsentField, groupIconResults,
  groupIconSearch, groupIconSearchButton, groupIconSearchStatus, groupIconSelection,
  groupIconSlugField, groupIconUpload, groupModalTitle, groupNameField, groupNewNameField,
  groupResetButton
} from './dom.js';
import { tr } from './i18n.js';
import { saveDashboardState } from './ui-state.js';

let iconSearchTimer = null;
let iconSearchRequest = null;
let groupIconUploadPreviewURL = null;
let selectedDashboardIconRemoteAllowed = false;

const normalizeIconSlug = (value) => value.trim().toLowerCase().replace(/\s+/g, '-');
const isUploadedIconRef = (value) => String(value || '').startsWith('upload:');
const buildIconUrl = (ref, allowRemote = false) => {
  const normalizedRef = String(ref || '').trim();
  if (!normalizedRef) {
    return '';
  }
  const remotePart = allowRemote && !isUploadedIconRef(normalizedRef) ? '&remote=1' : '';
  return `${appBase}icons/render?ref=${encodeURIComponent(normalizedRef)}${remotePart}`;
};

const clearGroupIconUploadPreviewURL = () => {
  if (groupIconUploadPreviewURL) {
    URL.revokeObjectURL(groupIconUploadPreviewURL);
    groupIconUploadPreviewURL = null;
  }
};

const clearGroupIconUploadSelection = () => {
  clearGroupIconUploadPreviewURL();
  if (groupIconUpload) {
    groupIconUpload.value = '';
  }
};

const updateGroupIconPreview = () => {
  const uploadFile = groupIconUpload?.files?.[0] || null;
  if (uploadFile) {
    clearGroupIconUploadPreviewURL();
    groupIconUploadPreviewURL = URL.createObjectURL(uploadFile);
    if (groupIconPreviewFrame) {
      groupIconPreviewFrame.hidden = false;
    }
    if (groupIconPreview) {
      groupIconPreview.src = groupIconUploadPreviewURL; // codeql[js/xss-through-dom]: groupIconUploadPreviewURL is a blob: URL created via URL.createObjectURL() from a user-selected file input, not DOM text.
    }
    if (groupIconSelection) {
      groupIconSelection.textContent = tr('groupIconSelectedUpload', 'Selected: custom uploaded icon');
    }
    return;
  }

  const currentRef = String(groupIconSlugField?.value || '').trim();
  const slug = isUploadedIconRef(currentRef)
    ? currentRef
    : normalizeIconSlug(currentRef);
  if (groupIconSlugField) {
    groupIconSlugField.value = slug;
  }
  if (groupIconSelection) {
    groupIconSelection.textContent = slug
      ? (isUploadedIconRef(slug)
        ? tr('groupIconSelectedUpload', 'Selected: custom uploaded icon')
        : tr('groupIconSelectedSlug', 'Selected: {slug}', { slug }))
      : tr('groupIconNoneSelected', 'No icon selected.');
  }
  const iconUrl = buildIconUrl(slug, selectedDashboardIconRemoteAllowed);
  if (!iconUrl) {
    if (groupIconPreviewFrame) {
      groupIconPreviewFrame.hidden = true;
    }
    groupIconPreview?.removeAttribute('src');
    return;
  }
  if (groupIconPreviewFrame) {
    groupIconPreviewFrame.hidden = false;
  }
  if (groupIconPreview) {
    groupIconPreview.src = iconUrl;
  }
};

const renderIconResults = (results, query) => {
  if (!groupIconResults) {
    return;
  }
  const normalizedQuery = normalizeIconSlug(query || '');
  const selectedValue = String(groupIconSlugField?.value || '').trim();
  groupIconResults.innerHTML = '';

  if (normalizedQuery) {
    const useCustomButton = document.createElement('button');
    useCustomButton.type = 'button';
    useCustomButton.className = `group-icon-result${selectedValue === normalizedQuery ? ' is-selected' : ''}`;
    const customBody = document.createElement('div');
    customBody.className = 'group-icon-result-body';
    const customTitle = document.createElement('strong');
    customTitle.textContent = tr('groupIconUseCustomSlug', 'Use custom slug');
    const customSlug = document.createElement('span');
    customSlug.className = 'muted compact';
    customSlug.textContent = normalizedQuery;
    customBody.appendChild(customTitle);
    customBody.appendChild(customSlug);
    useCustomButton.appendChild(customBody);
    useCustomButton.addEventListener('click', () => {
      clearGroupIconUploadSelection();
      selectedDashboardIconRemoteAllowed = false;
      if (groupIconRemoteConsentField) {
        groupIconRemoteConsentField.value = '';
      }
      if (groupIconSlugField) {
        groupIconSlugField.value = normalizedQuery;
      }
      updateGroupIconPreview();
      renderIconResults(results, query);
    });
    groupIconResults.appendChild(useCustomButton);
  }

  results.forEach((result) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `group-icon-result${selectedValue === result.value ? ' is-selected' : ''}`;
    const previewImage = document.createElement('img');
    previewImage.src = result.url;
    previewImage.alt = result.label;
    previewImage.loading = 'lazy';
    const body = document.createElement('div');
    body.className = 'group-icon-result-body';
    const titleNode = document.createElement('strong');
    titleNode.textContent = result.label;
    const slugNode = document.createElement('span');
    slugNode.className = 'muted compact';
    slugNode.textContent = result.source === 'upload' ? `Upload · ${result.slug}` : result.slug;
    body.appendChild(titleNode);
    body.appendChild(slugNode);
    if (result.preferred) {
      const badge = document.createElement('span');
      badge.className = 'muted compact';
      badge.textContent = tr('groupIconAlreadyPresent', 'Already present');
      body.appendChild(badge);
    }
    button.appendChild(previewImage);
    button.appendChild(body);
    previewImage.addEventListener('error', () => {
      previewImage.hidden = true;
    });
    button.addEventListener('click', () => {
      clearGroupIconUploadSelection();
      selectedDashboardIconRemoteAllowed = result.source !== 'upload';
      if (groupIconRemoteConsentField) {
        groupIconRemoteConsentField.value = selectedDashboardIconRemoteAllowed ? '1' : '';
      }
      if (groupIconSlugField) {
        groupIconSlugField.value = result.value;
      }
      updateGroupIconPreview();
      renderIconResults(results, query);
    });
    groupIconResults.appendChild(button);
  });

  if (groupIconSearchStatus) {
    if (!normalizedQuery) {
      groupIconSearchStatus.textContent = tr('groupIconSearchHint', 'Search by name, aliases, or categories.');
    } else if (results.length > 0) {
      groupIconSearchStatus.textContent = tr('groupIconSearchResultsCount', '{count} matching icons found.', { count: results.length });
    } else {
      groupIconSearchStatus.textContent = tr('groupIconSearchNoResults', 'No matches found. You can use the slug directly.');
    }
  }
};

const runIconSearch = async (query) => {
  const normalizedQuery = query.trim();
  if (iconSearchRequest) {
    iconSearchRequest.abort();
  }
  iconSearchRequest = new AbortController();
  try {
    const response = await fetch(`${appBase}icons/search?q=${encodeURIComponent(normalizedQuery)}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: iconSearchRequest.signal
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    renderIconResults(Array.isArray(payload.results) ? payload.results : [], normalizedQuery);
  } catch (error) {
    if (error.name === 'AbortError') {
      return;
    }
    renderIconResults([], normalizedQuery);
    if (groupIconSearchStatus) {
      groupIconSearchStatus.textContent = tr('groupIconSearchUnavailable', 'Icon search is currently unavailable. You can still set the slug directly.');
    }
  }
};

const hasIconSearchConsent = () =>
  localStorage.getItem('goup_icon_search_consent') === '1';

const triggerIconSearch = () => {
  const query = groupIconSearch?.value || '';
  if (!hasIconSearchConsent()) {
    if (groupIconConsentPanel) groupIconConsentPanel.hidden = false;
    if (groupIconSearchStatus) groupIconSearchStatus.textContent = '';
    return;
  }
  if (groupIconConsentPanel) groupIconConsentPanel.hidden = true;
  scheduleIconSearch(query);
};

const scheduleIconSearch = (query) => {
  if (iconSearchTimer) {
    window.clearTimeout(iconSearchTimer);
  }
  iconSearchTimer = window.setTimeout(() => runIconSearch(query), 180);
};

export const openGroupDialog = (button) => {
  if (!groupModalTitle || !groupNameField || !groupIconSearch || !groupIconSlugField || !groupDialog) {
    return;
  }
  const groupName = button.dataset.group || tr('groupFallback', 'Group');
  const iconValue = String(button.dataset.iconSlug || '').trim();
  groupModalTitle.textContent = tr('groupModalTitle', 'Configure group · {name}', { name: groupName });
  groupNameField.value = groupName;
  if (groupNewNameField) groupNewNameField.value = groupName;
  clearGroupIconUploadSelection();
  selectedDashboardIconRemoteAllowed = false;
  if (groupIconRemoteConsentField) {
    groupIconRemoteConsentField.value = '';
  }
  groupIconSearch.value = !isUploadedIconRef(iconValue) && iconValue ? normalizeIconSlug(iconValue) : groupName;
  groupIconSlugField.value = iconValue;
  updateGroupIconPreview();
  renderIconResults([], groupIconSearch?.value || '');
  if (groupIconConsentPanel) groupIconConsentPanel.hidden = true;
  groupDialog.showModal();
};

export function initGroupDialog() {
  groupIconPreview?.addEventListener('error', () => {
    if (groupIconPreviewFrame) {
      groupIconPreviewFrame.hidden = true;
    }
    groupIconPreview.removeAttribute('src');
  });

  groupCancelButton?.addEventListener('click', () => groupDialog?.close());
  bindDialogBackdropClose(groupDialog);

  groupResetButton?.addEventListener('click', () => {
    clearGroupIconUploadSelection();
    selectedDashboardIconRemoteAllowed = false;
    if (groupIconRemoteConsentField) {
      groupIconRemoteConsentField.value = '';
    }
    if (groupIconSearch) {
      groupIconSearch.value = groupNameField?.value || '';
    }
    if (groupIconSlugField) {
      groupIconSlugField.value = '';
    }
    updateGroupIconPreview();
    renderIconResults([], groupIconSearch?.value || '');
  });

  groupIconSearch?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      triggerIconSearch();
    }
  });
  groupIconSearchButton?.addEventListener('click', () => triggerIconSearch());
  groupIconConsentConfirm?.addEventListener('click', () => {
    localStorage.setItem('goup_icon_search_consent', '1');
    if (groupIconConsentPanel) groupIconConsentPanel.hidden = true;
    scheduleIconSearch(groupIconSearch?.value || '');
  });
  groupIconUpload?.addEventListener('change', () => {
    if (groupIconUpload?.files?.length) {
      selectedDashboardIconRemoteAllowed = false;
      if (groupIconRemoteConsentField) {
        groupIconRemoteConsentField.value = '';
      }
      if (groupIconSlugField) {
        groupIconSlugField.value = '';
      }
    }
    updateGroupIconPreview();
  });
  groupForm?.addEventListener('submit', saveDashboardState);
}
