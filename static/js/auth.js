/* static/js/auth.js
   Shared auth helpers (SERVER MODE) for Aftab CRM
   Uses Flask backend API (shared DB across browsers)

   Endpoints:
   - POST   /api/login
   - POST   /api/logout
   - GET    /api/me
   - POST   /api/register                      (public register with adminPassword)
   - GET    /api/users                         (admin)
   - GET    /api/users/<username>/logs         (admin)
   - POST   /api/admin/users                   (admin create)
   - PUT    /api/admin/users/<id>              (admin update)
   - DELETE /api/admin/users/<id>              (admin delete)
   - POST   /api/admin/users/clear             (admin clear)
*/
(() => {
  const API = {
    login: "/api/login",
    logout: "/api/logout",
    me: "/api/me",
    register: "/api/register",

    users: "/api/users",
    userLogs: (username) => `/api/users/${encodeURIComponent(username)}/logs`,

    adminCreate: "/api/admin/users",
    adminUpdate: (id) => `/api/admin/users/${encodeURIComponent(id)}`,
    adminDelete: (id) => `/api/admin/users/${encodeURIComponent(id)}`,
    adminClear: "/api/admin/users/clear"
  };

  // Legacy labels (not used in server mode)
  const AUTH_DB_NAME = "aftab_auth_db";
  const AUTH_DB_VERSION = 999;
  const USERS_STORE = "users";
  const LOGS_STORE = "logs";

  function safeLower(v){ return String(v ?? "").trim().toLowerCase(); }

  async function jsonFetch(url, opts = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...(opts.headers || {})
    };

    const res = await fetch(url, {
      ...opts,
      headers,
      credentials: "include",  // ✅ always send/receive session cookie
      cache: "no-store"
    });

    let data = null;
    try { data = await res.json(); } catch(_) {}

    if (!res.ok) {
      const err = (data && (data.error || data.message)) || `http_${res.status}`;
      const e = new Error(err);
      e.status = res.status;
      e.payload = data;
      throw e;
    }
    return data;
  }

  // ===== Session helpers =====
  async function authMe(){
    return jsonFetch(API.me, { method: "GET" });
  }

  async function authLogin(username, password){
    const data = await jsonFetch(API.login, {
      method: "POST",
      body: JSON.stringify({ username: String(username||"").trim(), password: String(password||"") })
    });

    if (data?.ok) {
      localStorage.setItem("alg_session_username", data.username);
      localStorage.setItem("alg_session_role", data.role);
      if (data.company) localStorage.setItem("alg_session_company", data.company);
    }
    return data;
  }

  async function authLogout(){
    const data = await jsonFetch(API.logout, { method: "POST", body: JSON.stringify({}) });
    localStorage.removeItem("alg_session_username");
    localStorage.removeItem("alg_session_role");
    localStorage.removeItem("alg_session_company");
    return data;
  }

  // ===== Public register (from login.html) =====
  async function authRegister(user){
    // user MUST contain adminPassword for server to accept
    let payload = user;
    if (typeof payload === "string") {
      try { payload = JSON.parse(payload); } catch(e) { payload = {}; }
    }
    return jsonFetch(API.register, {
      method: "POST",
      body: JSON.stringify(payload || {})
    });
  }

  // ===== Users (admin list) =====
  async function authGetAllUsers(){
    const data = await jsonFetch(API.users, { method: "GET" });
    return data.users || [];
  }

  async function authGetByCompanyUsername(company, username){
    // company ignored in server mode
    const u = safeLower(username);
    const list = await authGetAllUsers();
    return list.find(x => safeLower(x.username) === u) || null;
  }

  // ===== Admin CRUD =====
  async function adminCreateUser(user){
    // user = {company, username, role, fullName, email, phone, passwordPlain, isActive}
    let payload = user;
    if (typeof payload === "string") {
      try { payload = JSON.parse(payload); } catch(e) { payload = {}; }
    }
    return jsonFetch(API.adminCreate, {
      method: "POST",
      body: JSON.stringify(payload || {})
    });
  }

  async function adminUpdateUser(id, patch){
    return jsonFetch(API.adminUpdate(id), {
      method: "PUT",
      body: JSON.stringify(patch || {})
    });
  }

  async function adminDeleteUser(id){
    return jsonFetch(API.adminDelete(id), { method: "DELETE" });
  }

  async function adminClearUsers(){
    return jsonFetch(API.adminClear, { method: "POST", body: JSON.stringify({}) });
  }

  // ===== Logs =====
  async function authGetLogsByCompanyUsername(company, username, limit=200){
    const data = await jsonFetch(API.userLogs(username), { method: "GET" });
    const rows = data.logs || [];
    const lim = Number(limit);
    return rows.slice(0, (Number.isFinite(lim) && lim > 0) ? lim : 200);
  }

  // keep for compatibility (no-op)
  async function authLog(){ return true; }

  // ===== Utils =====
  function uuid(){
    return crypto.randomUUID ? crypto.randomUUID() : "id-" + Math.random().toString(16).slice(2) + Date.now();
  }
  async function sha256(text){
    const enc = new TextEncoder();
    const data = enc.encode(String(text ?? ""));
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
  }
  function sanitize(v){ return (v || "").toString().trim(); }
  function onlyDigits(v){ return (v || "").toString().replace(/\D+/g, ""); }
  function buildE164(countryCode, localNumber){
    const digits = onlyDigits(localNumber);
    if(!digits) return "";
    const cc = String(countryCode || "").trim();
    if(!cc.startsWith("+")) return `+${onlyDigits(cc)}${digits}`;
    return `${cc}${digits}`;
  }

  async function openAuthDB(){ return null; }

  window.ALG_AUTH = {
    AUTH_DB_NAME,
    AUTH_DB_VERSION,
    USERS_STORE,
    LOGS_STORE,

    openAuthDB,

    // Session
    authMe,
    authLogin,
    authLogout,

    // Public register
    authRegister,

    // Users
    authGetByCompanyUsername,
    authGetAllUsers,

    // Admin
    adminCreateUser,
    adminUpdateUser,
    adminDeleteUser,
    adminClearUsers,

    // Logs
    authLog,
    authGetLogsByCompanyUsername,

    // Utils
    uuid,
    sha256,
    sanitize,
    onlyDigits,
    buildE164
  };
})();
