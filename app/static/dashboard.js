// Dashboard client logic for the JWT bearer path.
//
// This file is served from the same origin (/static/dashboard.js), so it is
// allowed by the SECURE profile's Content-Security-Policy (script-src 'self').
// Injected inline <script> payloads (the S3 attack) are NOT same-origin script
// files, so the same CSP blocks them — which is exactly the defence being shown.
//
// Server-side values are passed via data-* attributes on #app-config rather than
// inline template interpolation, so no inline script is required.

(function () {
  const cfg = document.getElementById("app-config");
  const PROFILE = cfg.dataset.profile;
  const JWT_STORAGE = cfg.dataset.jwtStorage;
  const USERNAME = cfg.dataset.username;

  const tokenDisplay = () => document.getElementById("token-display");
  const apiOut = () => document.getElementById("api-me-output");

  // ── Token storage helpers ──────────────────────────────────────────────
  // localStorage    → INSECURE: readable by any same-origin script (S3 sink)
  // httponly_cookie → SECURE: set by the server as HttpOnly; JS never sees it

  function storeToken(token) {
    if (JWT_STORAGE === "localStorage") {
      localStorage.setItem("jwt", token);
      tokenDisplay().textContent = token;
    } else {
      tokenDisplay().textContent =
        "Token is in an HttpOnly cookie — not readable by JavaScript.\n" +
        "Check DevTools → Application → Cookies → access_token.";
    }
  }

  function loadToken() {
    if (JWT_STORAGE === "localStorage") {
      return localStorage.getItem("jwt");
    }
    return null; // cookie mode: browser sends it automatically
  }

  function clearToken() {
    if (JWT_STORAGE === "localStorage") {
      localStorage.removeItem("jwt");
    }
    tokenDisplay().textContent = "— cleared —";
  }

  // ── API actions ────────────────────────────────────────────────────────

  async function apiLogin() {
    const password = prompt("Enter your password for the API login:");
    if (!password) return;

    const resp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password }),
    });
    const data = await resp.json();

    if (data.token) {
      // INSECURE path: token arrives in response body → store in localStorage
      storeToken(data.token);
      apiOut().textContent = "Token obtained. Storage: " + data.storage;
    } else if (data.message === "Logged in") {
      // SECURE path: token was set as an HttpOnly cookie by the server
      storeToken(null);
      apiOut().textContent =
        "Logged in. Token delivered as HttpOnly cookie — not exposed to JavaScript.";
    } else {
      apiOut().textContent = JSON.stringify(data);
    }
  }

  async function callApiMe() {
    let fetchOpts = {};
    if (JWT_STORAGE === "localStorage") {
      const token = loadToken();
      if (!token) {
        apiOut().textContent = "No token in localStorage — click API Login first.";
        return;
      }
      fetchOpts = { headers: { Authorization: "Bearer " + token } };
    }
    // httponly_cookie: no Authorization header — browser sends cookie automatically

    const resp = await fetch("/api/me", fetchOpts);
    const data = await resp.json();
    apiOut().textContent = JSON.stringify(data, null, 2) + "\n\nHTTP " + resp.status;
  }

  async function apiLogout() {
    let fetchOpts = { method: "POST" };
    if (JWT_STORAGE === "localStorage") {
      const token = loadToken();
      if (token) {
        fetchOpts.headers = { Authorization: "Bearer " + token };
      }
    }
    // httponly_cookie: server reads the cookie directly

    await fetch("/api/logout", fetchOpts);
    clearToken();

    apiOut().textContent =
      PROFILE === "INSECURE"
        ? "Client-side token cleared.\nS4: Server did NOT revoke it — paste the token into curl to verify it still works."
        : "Token revoked server-side. Any replay attempt will return 401.";
  }

  // ── Wire up buttons (no inline onclick — blocked by strict CSP) ──────────
  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("btn-api-login").addEventListener("click", apiLogin);
    document.getElementById("btn-api-me").addEventListener("click", callApiMe);
    document.getElementById("btn-api-logout").addEventListener("click", apiLogout);
  });
})();
