/* /js/auth.js
 * Supabase Auth + (legacy local users kept for admin.js compatibility)
 *
 * Login strategy:
 * - User enters "username" + "password"
 * - We sign in to Supabase using email = `${username}@tdg.com`
 * - Role / driverNumber / displayName are read from public.tdg_profiles (id = auth.users.id)
 *
 * Requirements in HTML:
 * 1) <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
 * 2) window.SUPABASE_URL + window.SUPABASE_ANON_KEY set before this file
 * 3) window.supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
 */
(() => {
  const LS_USERS = "tdg_users_v1";         // legacy local users (admin.js)
  const SS_SESSION = "tdg_session_v1";     // legacy session cache (used by app.js)

  const nowIso = () => new Date().toISOString();
  const uid = () =>
    "U" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  const safe = (s) => String(s ?? "").trim();

  function getSupabaseClient() {
    // Preferred: app already created window.supabaseClient
    if (window.supabaseClient?.auth && window.supabaseClient?.from) return window.supabaseClient;

    // Fallback: create client if supabase-js loaded and env vars present
    try {
      const url = window.SUPABASE_URL;
      const key = window.SUPABASE_ANON_KEY;
      if (window.supabase?.createClient && url && key) {
        window.supabaseClient = window.supabase.createClient(url, key);
        return window.supabaseClient;
      }
    } catch {}
    return null;
  }

  async function sha256(text) {
    const enc = new TextEncoder().encode(text);
    const buf = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // ---------------------------
  // Legacy local users (kept so admin.js doesn't crash before you migrate it)
  // ---------------------------
  async function ensureSeedAdmin() {
    const list = getUsers();
    if (list.length) return;

    const admin = {
      id: uid(),
      username: "admin",
      displayName: "Administrator",
      role: "admin", // admin | driver | viewer
      driverNumber: "admin",
      vehicleNo: "",
      phone: "",
      email: "admin@tdg.com",
      isActive: true,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      passwordHash: await sha256("Admin@1234"),
      mustChangePassword: true,
      lastLoginAt: "",
    };

    localStorage.setItem(LS_USERS, JSON.stringify([admin]));
  }

  function getUsers() {
    try {
      return JSON.parse(localStorage.getItem(LS_USERS) || "[]");
    } catch {
      return [];
    }
  }

  function setUsers(users) {
    localStorage.setItem(LS_USERS, JSON.stringify(users));
  }

  // ---------------------------
  // Session cache (sync, for existing pages)
  // ---------------------------
  function getSession() {
    try {
      return JSON.parse(sessionStorage.getItem(SS_SESSION) || "null");
    } catch {
      return null;
    }
  }

  function setSession(sess) {
    sessionStorage.setItem(SS_SESSION, JSON.stringify(sess));
  }

  function clearSession() {
    sessionStorage.removeItem(SS_SESSION);
  }

  function requireAuth({ roles } = {}) {
    const sess = getSession();
    if (!sess || !sess.userId) {
      window.location.href = "./login.html";
      return null;
    }
    if (Array.isArray(roles) && roles.length && !roles.includes(sess.role)) {
      alert("权限不足（Access Denied）");
      window.location.href = "./index.html";
      return null;
    }
    return sess;
  }

  // ---------------------------
  // Supabase-based authentication
  // ---------------------------
  async function fetchProfileByUserId(userId) {
    const sb = getSupabaseClient();
    if (!sb) throw new Error("Supabase client not initialized");

    const { data, error } = await sb
      .from("tdg_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    if (error) throw error;
    return data;
  }

  async function refreshSessionFromSupabase() {
    const sb = getSupabaseClient();
    if (!sb?.auth) return null;

    const { data, error } = await sb.auth.getSession();
    if (error) return null;

    const user = data?.session?.user;
    if (!user) return null;

    try {
      const profile = await fetchProfileByUserId(user.id);
      const sess = {
        userId: user.id,
        username: profile?.username || safe(user.email).split("@")[0],
        displayName: profile?.display_name || profile?.username || safe(user.email).split("@")[0],
        role: profile?.role || "driver",
        driverNumber: profile?.driver_number || profile?.username || "",
        vehicleNo: profile?.vehicle_no || "",
        loginAt: nowIso(),
      };
      setSession(sess);
      return sess;
    } catch {
      // If profile can't be read, still keep basic session
      const fallback = {
        userId: user.id,
        username: safe(user.email).split("@")[0],
        displayName: safe(user.email).split("@")[0],
        role: "driver",
        driverNumber: safe(user.email).split("@")[0],
        vehicleNo: "",
        loginAt: nowIso(),
      };
      setSession(fallback);
      return fallback;
    }
  }

  // Keep return shape compatible with existing login.html usage:
  // { ok: boolean, msg?: string, user?: object }
  async function authenticate(username, password) {
    const u = safe(username).toLowerCase();
    const p = safe(password);

    // 1) Supabase Auth
    try {
      const sb = getSupabaseClient();
      if (!sb?.auth) throw new Error("Supabase client not initialized");

      const email = `${u}@tdg.com`;
      const { data, error } = await sb.auth.signInWithPassword({ email, password: p });
      if (error) return { ok: false, msg: error.message };

      const userId = data?.user?.id;
      if (!userId) return { ok: false, msg: "Login failed (no user id)" };

      const profile = await fetchProfileByUserId(userId);

      if (profile && profile.is_active === false) {
        // If you disable users via tdg_profiles.is_active
        await sb.auth.signOut();
        clearSession();
        return { ok: false, msg: "用户已停用" };
      }

      const sess = {
        userId,
        username: profile?.username || u,
        displayName: profile?.display_name || profile?.username || u,
        role: profile?.role || "driver",
        driverNumber: profile?.driver_number || profile?.username || u,
        vehicleNo: profile?.vehicle_no || "",
        loginAt: nowIso(),
      };
      setSession(sess);

      // Keep legacy profile key in localStorage for other pages
setSession(sess);

// Keep legacy profile key in localStorage for other pages
syncProfileToLegacyLS();

// ✅ 登录成功后：先把 customers 从 Supabase 下载到本地缓存（tdg_customers_demo_v2）
try {
  if (window.TDG_SYNC?.downloadCustomersToLocal) {
    const n = await window.TDG_SYNC.downloadCustomersToLocal();
    console.log("customers synced:", n);
  } else {
    console.warn("TDG_SYNC.downloadCustomersToLocal not found (check supabaseSync.js load order)");
  }
} catch (e) {
  console.error("customers sync failed:", e);
}

return { ok: true, user: profile || { id: userId, username: u } };
    } catch (e) {
      // Continue to legacy fallback only if Supabase not configured / offline
    }

    // 2) Legacy local authentication fallback (temporary)
    await ensureSeedAdmin();
    const users = getUsers();
    const found = users.find((x) => (x.username || "").toLowerCase() === u);

    if (!found) return { ok: false, msg: "用户不存在（Supabase 未配置或离线）" };
    if (!found.isActive) return { ok: false, msg: "用户已停用" };

    const ph = await sha256(p);
    if (ph !== found.passwordHash) return { ok: false, msg: "密码错误" };

    found.lastLoginAt = nowIso();
    found.updatedAt = nowIso();
    setUsers(users);

    setSession({
      userId: found.id,
      username: found.username,
      displayName: found.displayName,
      role: found.role,
      driverNumber: found.driverNumber || "",
      vehicleNo: found.vehicleNo || "",
      loginAt: nowIso(),
    });

    syncProfileToLegacyLS();
    return { ok: true, user: found };
  }

  async function logout() {
    try {
      const sb = getSupabaseClient();
      await sb?.auth?.signOut?.();
    } catch {}
    clearSession();
    window.location.href = "./login.html";
  }

  function syncProfileToLegacyLS() {
    const sess = getSession();
    if (!sess) return;
    const LS_PROFILE = "tdg_user_profile_v2";
    const profile = {
      driverNumber: sess.driverNumber || "",
      driverName: sess.displayName || sess.username || "",
      vehicleNo: sess.vehicleNo || "",
    };
    try {
      localStorage.setItem(LS_PROFILE, JSON.stringify(profile));
    } catch {}
  }

  // Try to refresh cached session on load (non-blocking)
  // so pages opened in a new tab can reuse Supabase session.
  (async () => {
    try {
      await refreshSessionFromSupabase();
    } catch {}
  })();

  window.TDG_AUTH = {
    // legacy user management (admin.js will be migrated later)
    ensureSeedAdmin,
    getUsers,
    setUsers,
    sha256,

    // auth API used by pages
    authenticate,
    getSession,
    requireAuth,
    logout,
    syncProfileToLegacyLS,

    // optional helper
    refreshSessionFromSupabase,
  };
})();
