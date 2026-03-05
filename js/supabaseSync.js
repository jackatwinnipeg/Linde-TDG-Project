// /js/supabaseSync.js
(() => {
  "use strict";

  // LocalStorage keys used across the app
  const StorageKeys = {
    customers: "tdg_customers_demo_v2",
    customersLastSync: "tdg_last_sync_customers_v1",
    customersPendingOps: "tdg_customers_pending_ops_v1",
  };

  const safe = (v) => String(v ?? "").trim();

  function todayLocalISODate() {
    // YYYY-MM-DD in local timezone
    const d = new Date();
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }

  function getClient() {
    const sb = window.supabaseClient || window.supabase;
    if (!sb) throw new Error("Supabase client 未初始化（检查 supabaseClient.js）");
    return sb;
  }

  function normalizeCustomer(c) {
    return {
      accountNumber: safe(c.accountNumber),
      accountName: safe(c.accountName),
      accountAddress: safe(c.accountAddress),
      city: safe(c.city),
      route: safe(c.route),
    };
  }

  function readPendingOps() {
    try {
      return JSON.parse(localStorage.getItem(StorageKeys.customersPendingOps) || "[]");
    } catch {
      return [];
    }
  }

  function writePendingOps(ops) {
    localStorage.setItem(StorageKeys.customersPendingOps, JSON.stringify(Array.isArray(ops) ? ops : []));
  }

  function enqueueOp(op) {
    const ops = readPendingOps();
    ops.push(op);
    writePendingOps(ops);
  }

  async function downloadCustomersToLocal() {
    const sb = getClient();

    const { data, error } = await sb
      .from("customers")
      .select("accountNumber,accountName,accountAddress,city,route");

    if (error) throw error;

    const list = (data || []).map(normalizeCustomer);

    localStorage.setItem(StorageKeys.customers, JSON.stringify(list));
    return list.length;
  }

  async function upsertCustomersToServer(customers) {
    const sb = getClient();
    const payload = (Array.isArray(customers) ? customers : []).map(normalizeCustomer);

    if (!payload.length) return 0;

    // accountNumber is UNIQUE => use it for idempotent upsert
    const { error } = await sb
      .from("customers")
      .upsert(payload, { onConflict: "accountNumber" });

    if (error) throw error;
    return payload.length;
  }

  async function deleteCustomerFromServer(accountNumber) {
    const sb = getClient();
    const acct = safe(accountNumber);
    if (!acct) return 0;

    const { error } = await sb
      .from("customers")
      .delete()
      .eq("accountNumber", acct);

    if (error) throw error;
    return 1;
  }

  /**
   * Apply queued customer ops (upserts/deletes) to Supabase.
   * Keeps remaining ops if a failure happens (offline/RLS/etc).
   */
  async function flushPendingCustomerOps() {
    const ops = readPendingOps();
    if (!ops.length) return { ok: true, applied: 0, remaining: 0 };

    let applied = 0;
    const remaining = [];

    for (const op of ops) {
      try {
        if (op?.op === "upsert") {
          await upsertCustomersToServer([op.customer]);
          applied += 1;
        } else if (op?.op === "delete") {
          await deleteCustomerFromServer(op.accountNumber);
          applied += 1;
        } else {
          // unknown op: drop it
        }
      } catch (e) {
        // stop at first failure, keep this op and the rest
        remaining.push(op, ...ops.slice(applied));
        writePendingOps(remaining);
        return { ok: false, applied, remaining: remaining.length, error: e };
      }
    }

    // all applied
    writePendingOps([]);
    return { ok: true, applied, remaining: 0 };
  }

  /**
   * Daily sync policy:
   * - Every day, on first page visit, we pull latest customers from Supabase into localStorage.
   * - We also try to flush any pending local customer changes first (best effort).
   */
  async function ensureDailyCustomersSync({ force = false } = {}) {
    // Always try to flush pending ops; doesn't count as the "daily pull"
    try {
      await flushPendingCustomerOps();
    } catch {
      // ignore; download below may still work
    }

    const last = safe(localStorage.getItem(StorageKeys.customersLastSync));
    const today = todayLocalISODate();
    if (!force && last === today) return { ok: true, skipped: true, date: today };

    const n = await downloadCustomersToLocal();
    localStorage.setItem(StorageKeys.customersLastSync, today);
    return { ok: true, skipped: false, date: today, downloaded: n };
  }

  /**
   * Called by admin.js after local CRUD:
   * - queue op so we never "lose" changes if network/RLS fails temporarily
   * - try to push immediately
   */
  async function upsertCustomer(customer) {
    const c = normalizeCustomer(customer);
    enqueueOp({ op: "upsert", customer: c, ts: Date.now() });

    const r = await flushPendingCustomerOps();
    if (!r.ok) throw r.error;
    return true;
  }

  async function deleteCustomer(accountNumber) {
    const acct = safe(accountNumber);
    enqueueOp({ op: "delete", accountNumber: acct, ts: Date.now() });

    const r = await flushPendingCustomerOps();
    if (!r.ok) throw r.error;
    return true;
  }

  window.TDG_SYNC = {
    // customers
    downloadCustomersToLocal,
    ensureDailyCustomersSync,
    flushPendingCustomerOps,
    upsertCustomer,
    deleteCustomer,
    // helpers (optional)
    _keys: StorageKeys,
  };
})();
