// Simple auth helper shared across pages.
// Stores the JWT in localStorage so the session persists across reloads.

function getToken() {
  return localStorage.getItem('streesafe_token');
}

function getUser() {
  const raw = localStorage.getItem('streesafe_user');
  return raw ? JSON.parse(raw) : null;
}

function setSession(token, user) {
  localStorage.setItem('streesafe_token', token);
  localStorage.setItem('streesafe_user', JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem('streesafe_token');
  localStorage.removeItem('streesafe_user');
}

function authHeaders() {
  const token = getToken();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

async function registerUser(name, email, phone, password) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, phone, password })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Registration failed');
  }
  const data = await res.json();
  setSession(data.token, data.user);
  return data.user;
}

async function loginUser(email, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Login failed');
  }
  const data = await res.json();
  setSession(data.token, data.user);
  return data.user;
}

function logoutUser() {
  clearSession();
  window.location.reload();
}

function getResponderToken() {
  return localStorage.getItem('streesafe_responder_token');
}
function getResponder() {
  const raw = localStorage.getItem('streesafe_responder');
  return raw ? JSON.parse(raw) : null;
}
function setResponderSession(token, responder) {
  localStorage.setItem('streesafe_responder_token', token);
  localStorage.setItem('streesafe_responder', JSON.stringify(responder));
}
function clearResponderSession() {
  localStorage.removeItem('streesafe_responder_token');
  localStorage.removeItem('streesafe_responder');
}
function responderAuthHeaders() {
  const token = getResponderToken();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}
async function registerResponder(name, email, phone, password, lat, lng) {
  const res = await fetch(`${API_BASE}/responder-auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, phone, password, lat, lng })
  });
  if (!res.ok) { const err = await res.json(); throw new Error(err.detail || 'Registration failed'); }
  const data = await res.json();
  setResponderSession(data.token, data.responder);
  return data.responder;
}
async function loginResponder(email, password) {
  const res = await fetch(`${API_BASE}/responder-auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) { const err = await res.json(); throw new Error(err.detail || 'Login failed'); }
  const data = await res.json();
  setResponderSession(data.token, data.responder);
  return data.responder;
}
function logoutResponder() {
  clearResponderSession();
  window.location.reload();
}
