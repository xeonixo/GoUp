import { saveDashboardState } from './ui-state.js';

export const submitPost = (action, fields) => {
  saveDashboardState();
  const form = document.createElement('form');
  form.method = 'post';
  form.action = action;
  Object.entries(fields).forEach(([key, value]) => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = key;
    input.value = value;
    form.appendChild(input);
  });
  document.body.appendChild(form);
  form.submit();
};

export const postForm = async (action, fields) => {
  const payload = new URLSearchParams();
  Object.entries(fields).forEach(([key, value]) => {
    if (value === null || value === undefined) {
      return;
    }
    payload.set(key, String(value));
  });
  return fetch(action, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      Accept: 'application/json'
    },
    body: payload.toString()
  });
};
