

const DANGEROUS_CHARS = /[<>\/\\"';{}()\[\]`$&|*?~=+%]/g;

function validateUsernameClient(username) {
  if (typeof username !== 'string' || !username) {
    return { valid: false, error: 'Username is required' };
  }
  if (username.length < 3 || username.length > 50) {
    return { valid: false, error: 'Username must be between 3 and 50 characters' };
  }
  const pattern = /^[a-zA-Z0-9._-]+$/;
  if (!pattern.test(username) || DANGEROUS_CHARS.test(username)) {
    return { valid: false, error: 'Username has invalid characters' };
  }
  return { valid: true, value: username.trim() };
}

function validatePasswordClient(password) {
  if (typeof password !== 'string' || !password) {
    return { valid: false, error: 'Password is required' };
  }
  if (password.length < 6 || password.length > 200) {
    return { valid: false, error: 'Password must be between 6 and 200 characters' };
  }
  if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(password)) {
    return { valid: false, error: 'Password contains invalid control characters' };
  }
  return { valid: true, value: password };
}

function validateWebsiteLabelClient(label) {
  if (!label) {
    return { valid: false, error: 'Website is required' };
  }
  const pattern = /^[a-zA-Z0-9\s._:-]+$/;
  if (!pattern.test(label) || DANGEROUS_CHARS.test(label)) {
    return { valid: false, error: 'Website has invalid characters' };
  }
  return { valid: true, value: label.trim() };
}

function validatePasswordLabelClient(label) {
  if (!label) {
    return { valid: false, error: 'Label is required' };
  }
  const pattern = /^[a-zA-Z0-9\s._'-]+$/;
  if (!pattern.test(label) || DANGEROUS_CHARS.test(label)) {
    return { valid: false, error: 'Label has invalid characters' };
  }
  return { valid: true, value: label.trim() };
}

function validateNotesClient(notes) {
  if (!notes) return { valid: true, value: '' };
  if (notes.length > 1000) {
    return { valid: false, error: 'Notes too long' };
  }
  const pattern = /^[a-zA-Z0-9\s.,!?@#:_-]*$/;
  if (!pattern.test(notes) || DANGEROUS_CHARS.test(notes)) {
    return { valid: false, error: 'Notes contain invalid characters' };
  }
  return { valid: true, value: notes };
}

function validateField(inputEl, validator) {
  const res = validator(inputEl.value);
  if (!res.valid) {
    inputEl.classList.add('input-error');
  } else {
    inputEl.classList.remove('input-error');
  }
  return res;
}

window.inputValidation = {
  validateUsernameClient,
  validatePasswordClient,
  validateWebsiteLabelClient,
  validatePasswordLabelClient,
  validateNotesClient,
  validateField
};