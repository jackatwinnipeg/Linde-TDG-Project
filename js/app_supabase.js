// ---------------------------
      // Utilities
      // ---------------------------
      const $ = (id) => document.getElementById(id);

      // Clear customer/account fields for the next delivery record
      function resetAccountFieldsForNextRecord() {
        const ids = [
          "accountNumber",
          "accountName",
          "accountAddress",
          "accountCity",
          "accountRoute",
          "deliveredVolume",
          "notes",
        ];
        ids.forEach((id) => {
          const el = $(id);
          if (!el) return;
          el.value = id === "deliveredVolume" ? 0 : "";
        });

        // Clear search input + results (use real IDs in this page)
        const q = $("searchBox");
        if (q) q.value = "";
        const res = $("resultBox");
        if (res) {
          res.innerHTML = `
            <h3 style="margin: 0 0 8px 0;">Search result shows here</h3>
            <div class="muted">请搜索/填写下一个客户。</div>
          `;
        }

        $("accountNumber")?.focus();
      }

      function toast(title, msg) {
        const toastEl = $("toast");
        const titleEl = $("toastTitle");
        const msgEl = $("toastMsg");

        if (!toastEl || !titleEl || !msgEl) return;

        titleEl.textContent = title;
        msgEl.textContent = msg;
        toastEl.style.display = "block";

        clearTimeout(window.__toastTimer);
        window.__toastTimer = setTimeout(() => {
          toastEl.style.display = "none";
        }, 2200);
      }

      function setStatus(text) {
        const statusEl = $("statusTag");
        if (statusEl) statusEl.textContent = "Status：" + text;
      }

      function setPill(pillId, on) {
        const el = $(pillId);
        if (!el) return;
        if (on) {
          el.classList.remove("off");
        } else {
          el.classList.add("off");
        }
      }

      // Prevent iOS accidental double-tap zoom on buttons
      document.addEventListener(
        "dblclick",
        (e) => {
          if (e.target.closest("button")) e.preventDefault();
        },
        { passive: false },
      );

      // ---------------------------
      // State: Arrive + Shift time
      // ---------------------------
      let isArrived = false;
      let arrivalTime = "";

      let shiftStart = "";
      let shiftFinish = "";

      function nowHHMM() {
        const d = new Date();
        const hh = String(d.getHours()).padStart(2, "0");
        const mm = String(d.getMinutes()).padStart(2, "0");
        return `${hh}:${mm}`;
      }

      function renderArrivalUI() {
        setPill("arrivePill", isArrived);

        const deliveredVolume = $("deliveredVolume");
        const btnArrive = $("btnArrive");
        const arrivalTimeText = $("arrivalTimeText");

        if (deliveredVolume) deliveredVolume.disabled = !isArrived;
        if (btnArrive) btnArrive.disabled = isArrived;
        if (arrivalTimeText) {
          arrivalTimeText.textContent = `Arrival Time：${arrivalTime || "—"}`;
        }

        setStatus(isArrived ? "Arrived" : "Driving");
      }

      function renderShiftTime() {
        const s = shiftStart || "—";
        const f = shiftFinish || "—";
        const shiftTimeText = $("shiftTimeText");
        if (shiftTimeText) {
          shiftTimeText.textContent = `Shift Time：${s} → ${f}`;
        }
      }

      // ---------------------------
      // LocalStorage keys
      // ---------------------------
      const LS_CUSTOMERS = "tdg_customers_demo_v2";
      const LS_CUSTOMERS_FALLBACK = "tdg_customers_demo_v3";
      const LS_PROFILE = "tdg_user_profile_v3";
      const LS_YESTERDAY_BASE = "tdg_yesterday_v3";
      const LS_YESTERDAY_LEGACY = "tdg_yesterday_v3"; // legacy single-key (migration)
      const LS_DRAFT = "tdg_draft_v3";
      const LS_CYCLE = "tdg_week_cycle_v3";
      const LS_RECORDS = "tdg_records_v3";
      const LS_PENDING_SYNC = "tdg_pending_sync_v1";

      // ---------------------------
      // Per-driver Yesterday (enterprise)
      // ---------------------------
      function getDriverKeySafe() {
        const s = getAuthSessionSafe();
        return (s?.driverNumber || s?.username || "").trim() || "unknown";
      }

      function getYesterdayKey(driverKey) {
        const k = String(driverKey || "unknown").trim() || "unknown";
        return `${LS_YESTERDAY_BASE}__${k}`;
      }

      function migrateLegacyYesterdayIfAny(driverKey) {
        // If legacy key exists and per-driver doesn't, migrate once.
        try {
          const perKey = getYesterdayKey(driverKey);
          if (localStorage.getItem(perKey)) return;
          const legacy = localStorage.getItem(LS_YESTERDAY_LEGACY);
          if (!legacy) return;
          localStorage.setItem(perKey, legacy);
          // keep legacy for safety, or uncomment next line to delete:
          // localStorage.removeItem(LS_YESTERDAY_LEGACY);
        } catch {}
      }

      function loadYesterdayForDriver(driverKey) {
        try {
          const k = getYesterdayKey(driverKey);
          const raw = localStorage.getItem(k);
          return raw ? JSON.parse(raw) : null;
        } catch {
          return null;
        }
      }

      function saveYesterdayForDriver(driverKey, data) {
        try {
          const k = getYesterdayKey(driverKey);
          localStorage.setItem(k, JSON.stringify(data));
        } catch {}
      }
      // ---------------------------
      // Helper functions
      // ---------------------------
      function getCustomers() {
        try {
          const raw = localStorage.getItem(LS_CUSTOMERS);
          if (raw) return JSON.parse(raw);

          // fallback: migrate from older key once
          const old = localStorage.getItem(LS_CUSTOMERS_FALLBACK);
          if (old) {
            const list = JSON.parse(old);
            localStorage.setItem(LS_CUSTOMERS, JSON.stringify(list));
            return list;
          }
          return [];
        } catch {
          return [];
        }
      }

      // ---------------------------
      // Customer sync (server -> localStorage)
      // ---------------------------
      async function syncCustomersFromServer({ silent = true } = {}) {
        // Requires login (token) because /api/customers is protected on the server
        const token = getAuthTokenSafe();
        if (!token) {
          if (!silent) toast("未登录", "无法从服务器同步客户（需要先登录）。");
          return { ok: false, reason: "no_token" };
        }

        try {
          const res = await fetch("/api/customers", {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + token,
            },
          });

          if (res.status === 401 || res.status === 403) {
            if (!silent)
              toast("无权限", "没有权限读取客户库（请检查登录/角色）。");
            return { ok: false, reason: "unauthorized" };
          }

          if (!res.ok) {
            if (!silent) toast("同步失败", "服务器返回错误：" + res.status);
            return { ok: false, reason: "http_" + res.status };
          }

          const data = await res.json().catch(() => null);

          // Server may return either {items:[...]} or [...]
          const list = Array.isArray(data)
            ? data
            : (data && (data.items || data.customers)) || [];
          if (!Array.isArray(list)) {
            if (!silent) toast("同步失败", "服务器客户数据格式不正确。");
            return { ok: false, reason: "bad_format" };
          }

          localStorage.setItem(LS_CUSTOMERS, JSON.stringify(list));
          if (!silent)
            toast("已同步", `已从服务器同步 ${list.length} 条客户。`);
          return { ok: true, count: list.length };
        } catch (e) {
          if (!silent)
            toast("同步失败", "网络/服务器不可用，已继续使用本地客户库。");
          return { ok: false, reason: "network" };
        }
      }

      function getRecords() {
        try {
          return JSON.parse(localStorage.getItem(LS_RECORDS) || "[]");
        } catch {
          return [];
        }
      }

      function setRecords(list) {
        try {
          localStorage.setItem(LS_RECORDS, JSON.stringify(Array.isArray(list) ? list : []));
        } catch {}
      }


      function computeRemainingTDG(base, records) {
        const totalDelivered = records.reduce(
          (sum, r) => sum + (Number(r.deliveredVolume) || 0),
          0,
        );
        return {
          base: base || 0,
          totalDelivered: totalDelivered,
          remaining: (base || 0) - totalDelivered,
        };
      }

      // ---------------------------
      // Demo data
      // ---------------------------
      function seedDemoCustomers() {
        const customers = [
          {
            accountNumber: "1001",
            accountName: "Manitoba Hydro - South Station",
            accountAddress: "123 Example St, Winnipeg, MB",
            city: "Winnipeg",
            route: "R-01",
            routeType: "Local",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          {
            accountNumber: "1002",
            accountName: "EZ-Lazy Foods",
            accountAddress: "88 Market Rd, Winnipeg, MB",
            city: "Winnipeg",
            route: "R-01",
            routeType: "Local",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          {
            accountNumber: "2001",
            accountName: "North Plant",
            accountAddress: "5 Industrial Ave, Brandon, MB",
            city: "Brandon",
            route: "R-02",
            routeType: "Highway",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          {
            accountNumber: "3007",
            accountName: "TDG Customer Demo",
            accountAddress: "77 Demo Blvd, Dauphin, MB",
            city: "Dauphin",
            route: "R-03",
            routeType: "Remote",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        ];
        localStorage.setItem(LS_CUSTOMERS, JSON.stringify(customers));
        toast("已加载", "演示客户库已写入本地。");
        renderResults([]);
      }

      function searchCustomers(q) {
        q = (q || "").trim().toLowerCase();
        if (!q) return [];
        const list = getCustomers();
        return list.filter(
          (c) =>
            (c.accountNumber || "").toLowerCase().includes(q) ||
            (c.accountName || "").toLowerCase().includes(q) ||
            (c.accountAddress || "").toLowerCase().includes(q) ||
            (c.city || "").toLowerCase().includes(q) ||
            (c.route || c.routeType || "").toLowerCase().includes(q),
        );
      }

      // ---------------------------
      // Form model
      // ---------------------------
      function getFormData() {
        const sess = getAuthSessionSafe();
        return {
          driverNumber:
            sess?.driverNumber ||
            sess?.username ||
            $("driverNumber")?.value.trim() ||
            "",
          driverName:
            sess?.displayName ||
            sess?.username ||
            $("driverName")?.value.trim() ||
            "",
          date: $("date")?.value || "",
          vehicleNo: $("vehicleNo")?.value.trim() || "",
          startKm: Number($("startKm")?.value || 0),
          endKm: Number($("endKm")?.value || 0),
          totalKm: Number($("totalKm")?.value || 0),
          tdgVolume: Number($("tdgVolume")?.value || 0),
          tdgVolume: Number($("tdgVolume")?.value || 0),
          weekCycle: Number($("weekCycle")?.value || 1),
          shiftTimeStart: shiftStart,
          shiftTimeFinish: shiftFinish,
          arrived: isArrived,
          arrivalTime: arrivalTime,
          accountNumber: $("accountNumber")?.value.trim() || "",
          accountName: $("accountName")?.value.trim() || "",
          accountAddress: $("accountAddress")?.value.trim() || "",
          accountCity: $("accountCity")?.value.trim() || "",
          accountRoute: $("accountRoute")?.value.trim() || "",
          accountCity: $("accountCity")?.value.trim() || "",
          accountRoute: $("accountRoute")?.value.trim() || "",
          deliveredVolume: Number($("deliveredVolume")?.value || 0),
          notes: $("notes")?.value.trim() || "",
          done: !$("donePill")?.classList.contains("off"),
          updatedAt: new Date().toISOString(),
        };
      }

      function setFormData(d) {
        if ($("date")) $("date").value = d.date || "";
        if ($("vehicleNo")) $("vehicleNo").value = d.vehicleNo || "";
        if ($("startKm")) $("startKm").value = d.startKm ?? "";
        if ($("endKm")) $("endKm").value = d.endKm ?? "";
        if ($("totalKm")) $("totalKm").value = d.totalKm ?? "";
        if ($("tdgVolume")) $("tdgVolume").value = d.tdgVolume ?? "";
        if ($("weekCycle")) $("weekCycle").value = String(d.weekCycle || 1);
        if ($("accountNumber"))
          $("accountNumber").value = d.accountNumber || "";
        if ($("accountName")) $("accountName").value = d.accountName || "";
        if ($("accountAddress"))
          $("accountAddress").value = d.accountAddress || "";
        if ($("accountCity")) $("accountCity").value = d.accountCity || "";
        if ($("accountRoute")) $("accountRoute").value = d.accountRoute || "";
        if ($("deliveredVolume"))
          $("deliveredVolume").value = d.deliveredVolume ?? "";
        if ($("notes")) $("notes").value = d.notes || "";

        shiftStart = d.shiftTimeStart || "";
        shiftFinish = d.shiftTimeFinish || "";
        renderShiftTime();

        isArrived = !!d.arrived;
        arrivalTime = d.arrivalTime || "";
        renderArrivalUI();

        setPill("donePill", !!d.done);

        // keep session state in sync
        saveIndexState();
      }

      // ---------------------------
      // Week cycle rotation 1-8
      // ---------------------------
      function loadWeekCycle() {
        const raw = localStorage.getItem(LS_CYCLE);
        const cycle = raw ? Number(raw) : 1;
        const weekCycle = $("weekCycle");
        if (weekCycle) {
          weekCycle.value = String(cycle >= 1 && cycle <= 8 ? cycle : 1);
        }
      }

      function rotateWeekCycle() {
        const weekCycle = $("weekCycle");
        if (!weekCycle) return;
        const current = Number(weekCycle.value || 1);
        const next = current >= 8 ? 1 : current + 1;
        localStorage.setItem(LS_CYCLE, String(next));
        weekCycle.value = String(next);
      }

      // ---------------------------
      // Simulated sources
      // ---------------------------
      function ensureDemoProfile() {
        if (localStorage.getItem(LS_PROFILE)) return;
        localStorage.setItem(
          LS_PROFILE,
          JSON.stringify({
            driverNumber: "D-001",
            driverName: "Driver Demo",
            vehicleNo: "VH-102",
          }),
        );
      }

      function loadFromProfile() {
        ensureDemoProfile();
        try {
          const p = JSON.parse(localStorage.getItem(LS_PROFILE) || "{}");
          if ($("driverNumber"))
            $("driverNumber").value = p.driverNumber || $("driverNumber").value;
          if ($("driverName"))
            $("driverName").value = p.driverName || $("driverName").value;
          if ($("vehicleNo"))
            $("vehicleNo").value = p.vehicleNo || $("vehicleNo").value;
          toast("已带入", "已从用户资料带入司机/车辆信息（演示）。");
        } catch {
          toast("错误", "无法加载用户资料");
        }
      
        saveIndexState();
      }

      function loadFromCalendar() {
        const today = new Date();
        const yyyy = today.getFullYear();
        const mm = String(today.getMonth() + 1).padStart(2, "0");
        const dd = String(today.getDate()).padStart(2, "0");
        if ($("date")) $("date").value = `${yyyy}-${mm}-${dd}`;

        const list = getCustomers();
        if (list.length) {
          const planned = list[0];
          if ($("accountNumber"))
            $("accountNumber").value = planned.accountNumber;
          if ($("accountName")) $("accountName").value = planned.accountName;
          if ($("accountAddress"))
            $("accountAddress").value = planned.accountAddress;
        }
        toast("已带入", "已从日历带入日期 + 计划客户（演示）。");
      
        saveIndexState();
      }

      function loadFromYesterday() {
        const driverKey = getDriverKeySafe();
        migrateLegacyYesterdayIfAny(driverKey);
        const y = loadYesterdayForDriver(driverKey);
        if (!y) {
          toast("暂无记录", "没有找到昨天记录（先 Save Draft 或 Done 一次）。");
          return;
        }
        try {
          setFormData({
            ...y,
            deliveredVolume: "",
            notes: "",
            done: false,
          });
          toast(
            "已带入",
            "已从昨天记录带入常用字段（Delivered/Notes 不复制）。",
          );
        } catch {
          toast("错误", "无法加载昨天记录");
        }
      
        saveIndexState();
      }

      function autoLoadVolumeFromYesterday() {
        const driverKey = getDriverKeySafe();
        migrateLegacyYesterdayIfAny(driverKey);
        const y = loadYesterdayForDriver(driverKey);
        if (!y) return;

        // Only autofill when empty/0 to avoid overwriting manual input
        const cur = Number($("tdgVolume")?.value || 0);
        if (!cur && y.remainingVolume != null) {
          $("tdgVolume").value = y.remainingVolume;
          toast("已带入", "TDG Volume 已自动带入前一天余数。");
        }
      }

      // ---------------------------
      // Search UI
      // ---------------------------
      function escapeHtml(s) {
        return String(s ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }

      function renderResults(items) {
        const box = $("resultBox");
        if (!box) return;

        if (!items.length) {
          box.innerHTML = `
            <h3 style="margin: 0 0 8px 0;">Search result shows here</h3>
            <div class="muted">没有匹配结果。换个关键词，或先加载演示客户库。</div>
          `;
          return;
        }

        const rows = items
          .map(
            (c, idx) => `
              <div style="padding:12px; border-radius:16px; border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.14); margin-top:10px;">
                <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start; flex-wrap:wrap;">
                  <div style="min-width:220px;">
                    <div style="font-weight:800; font-size:14px;">${escapeHtml(c.accountName)}</div>
                    <div class="muted" style="margin-top:6px;">${escapeHtml(c.accountAddress || "")}</div>
                    <div class="muted" style="margin-top:6px;">Account: ${escapeHtml(c.accountNumber)} | City: ${escapeHtml(c.city || "")} | Route: ${escapeHtml(c.route || c.routeType || "")}</div>
                  </div>
                  <button class="btn ok" data-pick="${idx}" type="button" style="min-width:120px;">Select</button>
                </div>
              </div>
            `,
          )
          .join("");

        box.innerHTML = `
          <h3 style="margin: 0 0 8px 0;">匹配到 ${items.length} 条客户</h3>
          <div class="muted">点击“Select”自动填充账号信息。</div>
          ${rows}
        `;

        box.querySelectorAll("[data-pick]").forEach((btn) => {
          btn.addEventListener(
            "click",
            () => {
              const i = Number(btn.getAttribute("data-pick"));
              const c = items[i];
              if ($("accountNumber"))
                $("accountNumber").value = c.accountNumber || "";
              if ($("accountName"))
                $("accountName").value = c.accountName || "";
              if ($("accountAddress"))
                $("accountAddress").value = c.accountAddress || "";
              toast("已选择客户", "已自动填充 Account / City / Route 字段。");
              if ($("accountCity")) $("accountCity").value = c.city || "";
              if ($("accountRoute"))
                $("accountRoute").value = c.route || c.routeType || "";
            },
            { passive: true },
          );
        });
      }

      // ---------------------------
      // Server backup functions
      // ---------------------------
      function getAuthSessionSafe() {
        try {
          return window.TDG_AUTH?.getSession?.() || null;
        } catch {
          return null;
        }
      }

      function getAuthTokenSafe() {
        return (
          localStorage.getItem("token") ||
          localStorage.getItem("access_token") ||
          localStorage.getItem("jwt") ||
          ""
        );
      }

      function enqueuePendingSync(payload, errorMsg) {
        try {
          const raw = localStorage.getItem(LS_PENDING_SYNC);
          const list = raw ? JSON.parse(raw) : [];
          list.push({
            createdAt: new Date().toISOString(),
            error: String(errorMsg || "unknown"),
            payload,
          });
          localStorage.setItem(LS_PENDING_SYNC, JSON.stringify(list));
        } catch {}
      }

      function buildDailyPayload(reason) {
        const form = getFormData();
        const records = getRecords();
        const baseTdg = Number($("tdgVolume")?.value || 0);
        const cal = computeRemainingTDG(baseTdg, records);
        const sess = getAuthSessionSafe();

        return {
          kind: "tdg_daily_log",
          version: 1,
          reason: reason || "manual",
          savedAt: new Date().toISOString(),
          date: form.date || "",
          driver: {
            employeeNumber: sess?.username || form.driverNumber || "",
            driverName: sess?.displayName || form.driverName || "",
            role: sess?.role || "",
          },
          vehicleNo: form.vehicleNo,
          weekCycle: form.weekCycle,
          shift: { start: shiftStart || "", finish: shiftFinish || "" },
          arriveState: { arrived: !!isArrived, arrivalTime: arrivalTime || "" },
          tdg: {
            base: cal.base,
            totalDelivered: cal.totalDelivered,
            remaining: cal.remaining,
          },
          form,
          records,
        };
      }

      async function postJsonWithTimeout(
        url,
        payload,
        { timeoutMs = 8000 } = {},
      ) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeoutMs);

        const token = getAuthTokenSafe();
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = "Bearer " + token;

        try {
          const res = await fetch(url, {
            method: "POST",
            headers,
            body: JSON.stringify(payload),
            signal: ctrl.signal,
          });

          const text = await res.text().catch(() => "");
          let data = null;
          try {
            data = text ? JSON.parse(text) : null;
          } catch {}

          return { ok: res.ok, status: res.status, data, text };
        } finally {
          clearTimeout(t);
        }
      }

      async function backupDailyToServer(reason = "manual") {
        const payload = buildDailyPayload(reason);

        // 1) Preferred: Supabase (Auth + RLS)
        try {
          const sb = window.supabaseClient;
          if (sb?.auth && sb?.from) {
            const uRes = await sb.auth.getUser();
            const user = uRes?.data?.user;
            if (!user) throw new Error("Not signed in (Supabase session missing)");

            const row = {
              owner_id: user.id,
              log_date: payload.date || null,
              driver_employee_number: payload?.driver?.employeeNumber || "",
              driver_name: payload?.driver?.driverName || "",
              driver_role: payload?.driver?.role || "",
              vehicle_no: payload.vehicleNo || null,
              week_cycle: payload.weekCycle ?? null,
              payload,
            };

            const ins = await sb
              .from("tdg_daily_logs")
              .insert(row)
              .select("id")
              .single();

            if (ins.error) throw ins.error;

            return {
              ok: true,
              url: "supabase:tdg_daily_logs",
              response: { id: ins.data?.id || null },
            };
          }
        } catch (e) {
          // Supabase failed -> continue to fallback endpoints + local queue
        }

        // 2) Fallback: legacy server endpoints (kept for compatibility)
        const endpoints = [
          "/api/daily-logs",
          "/api/dailylog",
          "/api/tdg/daily-logs",
          "/api/backup/daily",
          "/api/backup",
        ];

        for (const url of endpoints) {
          try {
            const r = await postJsonWithTimeout(url, payload, {
              timeoutMs: 9000,
            });
            if (r.ok) {
              return { ok: true, url, response: r.data || r.text || null };
            }
          } catch (e) {
            // continue trying
          }
        }

        enqueuePendingSync(payload, "Supabase + all endpoints failed");
        return { ok: false };
      }

// ---------------------------
// Supabase: record-level sync (Add Record)
// ---------------------------
function genClientRecordId() {
  try {
    return crypto.randomUUID();
  } catch {
    return "cr_" + Date.now() + "_" + Math.random().toString(16).slice(2);
  }
}

function buildRecordRowForSupabase(rec, ownerId) {
  // rec is the local record object we store in tdg_records_v3
  const workDate = rec.date || new Date().toISOString().slice(0, 10);
  return {
    client_record_id: rec.clientRecordId,
    owner_id: ownerId,

    driver_number: String(rec.driverNumber || rec.driver_number || ""),
    driver_name: String(rec.driverName || rec.driver_name || ""),
    work_date: workDate,
    vehicle_no: String(rec.vehicleNo || rec.vehicle_no || ""),
    week_cycle: rec.weekCycle ?? rec.week_cycle ?? null,
    shift_start: rec.shiftStart || rec.shift_start || "",
    shift_finish: rec.shiftFinish || rec.shift_finish || "",
    arrived: true,
    arrival_time: rec.arrivalTime || rec.arrival_time || "",
    completed_at: rec.completedAt || rec.completed_at || new Date().toISOString(),

    account_number: rec.accountNumber || rec.account_number || "",
    account_name: rec.accountName || rec.account_name || "",
    account_address: rec.accountAddress || rec.account_address || "",
    account_city: rec.accountCity || rec.account_city || "",
    account_route: rec.accountRoute || rec.account_route || "",

    tdg_volume: Number(rec.tdgVolume ?? rec.tdg_volume ?? 0) || null,
    delivered_volume: Number(rec.deliveredVolume ?? rec.delivered_volume ?? 0) || 0,
    notes: rec.notes || "",
    raw: rec,
  };
}

async function syncRecordToSupabase(rec) {
  const sb = window.supabaseClient;
  if (!sb?.auth || !sb?.from) throw new Error("Supabase client not initialized");

  const { data: userData, error: uErr } = await sb.auth.getUser();
  if (uErr) throw uErr;
  const user = userData?.user;
  if (!user) throw new Error("Auth session missing");

  if (!rec.clientRecordId) rec.clientRecordId = genClientRecordId();

  const row = buildRecordRowForSupabase(rec, user.id);

  // Upsert by client_record_id => idempotent / retry-safe
  const r = await sb
    .from("tdg_records")
    .upsert(row, { onConflict: "client_record_id" })
    .select("id")
    .single();

  if (r.error) throw r.error;
  return r;
}

async function syncAllLocalRecordsToSupabase() {
  const list = getRecords();
  // Sync sequentially to keep things simple and predictable
  for (const rec of list) {
    try {
      await syncRecordToSupabase(rec);
      rec.synced = true;
    } catch (e) {
      rec.synced = false;
      rec.syncError = String(e?.message || e);
    }
  }
  setRecords(list);
  return list;
}

async function uploadFinalDailyLogAndOffDuty(reason = "off_duty") {
  const sb = window.supabaseClient;
  if (!sb?.auth || !sb?.from) throw new Error("Supabase client not initialized");

  const { data: userData, error: uErr } = await sb.auth.getUser();
  if (uErr) throw uErr;
  const user = userData?.user;
  if (!user) throw new Error("Auth session missing");

  const payload = buildDailyPayload(reason);
  // IMPORTANT: We already sync each record into tdg_records.
  // This daily log is a "final snapshot", so disable trigger expansion to avoid duplicates.
  payload.meta = { ...(payload.meta || {}), skip_expand: true };

  const row = {
    owner_id: user.id,
    log_date: payload.date || null,
    driver_employee_number: payload?.driver?.employeeNumber || "",
    driver_name: payload?.driver?.driverName || "",
    driver_role: payload?.driver?.role || "",
    vehicle_no: payload.vehicleNo || null,
    week_cycle: payload.weekCycle ?? null,
    payload,
  };

  const ins = await sb.from("tdg_daily_logs").insert(row).select("id").single();
  if (ins.error) throw ins.error;
  return ins;
}


      async function logoutFlow() {
        const ok = confirm("Off Duty will sync all today's local records to Supabase, then upload a final daily snapshot. Continue?");
        if (!ok) return;

        const btn = $("btnLogout");
        if (btn) btn.disabled = true;

        try {
          toast("同步中…", "正在把本地记录逐条同步到云端数据库（可离线重试）。");

          // 1) Ensure all local records are synced (idempotent upsert)
          await syncAllLocalRecordsToSupabase();

          // 2) Upload final daily snapshot (skip trigger expansion to avoid duplicates)
          toast("上传汇总…", "正在上传当日最终汇总（Daily Log）。");
          await uploadFinalDailyLogAndOffDuty("off_duty");

          toast("完成", "已完成同步与汇总上传，正在退出…");

          // 3) Optionally clear today's local cache (keeps history in cloud)
          // If you prefer to keep local history, comment these lines.
          try {
            localStorage.removeItem(LS_RECORDS);
            localStorage.removeItem(LS_DRAFT);
          } catch {}

          // 4) Sign out
          try {
            await window.supabaseClient?.auth?.signOut?.();
          } catch {}
          try {
            window.TDG_AUTH?.logout?.();
            return;
          } catch {}

          window.location.href = "./login.html";
        } catch (e) {
          console.error(e);
          toast("失败", "Off Duty 同步/上传失败：请检查网络或稍后重试（本地记录未丢失）。");
        } finally {
          if (btn) btn.disabled = false;
        }
      }

      async function remoteBackupFlow() {
        const btn = $("btnRemoteBackup");
        if (btn) btn.disabled = true;

        toast(
          "远程备份…",
          "正在把当日数据上传到服务器（如失败会暂存本地队列）。",
        );
        const result = await backupDailyToServer("manual");
        if (btn) btn.disabled = false;

        if (result.ok) {
          toast("备份成功", `已保存到：${result.url}`);
        } else {
          toast("备份失败", "所有接口都不可用：已暂存到本地队列。");
        }
      }

      // ---------------------------
      // Actions
      // ---------------------------
      function confirmArrive() {
        if (isArrived) return;
        isArrived = true;
        arrivalTime = nowHHMM();
        renderArrivalUI();
        toast("到达确认", `已记录 Arrival Time：${arrivalTime}`);
      
        saveIndexState();
      }

      function checkIn() {
        if (shiftStart) {
          const ok = confirm(
            `已经有 Check-in：${shiftStart}。要覆盖为当前时间吗？`,
          );
          if (!ok) return;
        }
        shiftStart = nowHHMM();
        shiftFinish = "";
        renderShiftTime();
        toast("已 Check-in", `开始时间：${shiftStart}`);
      
        saveIndexState();
      }

      function checkOut() {
        if (!shiftStart) {
          alert("请先 Check-in（记录开始时间）");
          return;
        }
        if (shiftFinish) {
          const ok = confirm(
            `已经有 Check-out：${shiftFinish}。要覆盖为当前时间吗？`,
          );
          if (!ok) return;
        }
        shiftFinish = nowHHMM();
        renderShiftTime();
        toast("已 Check-out", `结束时间：${shiftFinish}`);
      
        saveIndexState();
      }

      function saveDraft() {
        const d = getFormData();
        // compute remaining for yesterday autofill
        const records = getRecords();
        const baseTdg = Number($("tdgVolume")?.value || 0);
        const cal = computeRemainingTDG(baseTdg, records);
        d.remainingVolume = cal.remaining;

        localStorage.setItem(LS_DRAFT, JSON.stringify(d));
        saveYesterdayForDriver(getDriverKeySafe(), d);
        toast("已保存", "草稿已保存到本地。");
      
        saveIndexState();
      }

      async function done() {
        // Prevent double-tap / duplicate submissions
        if (window.__savingDone) return;
        window.__savingDone = true;

        try {
          if (!isArrived) {
            toast("请先到达确认", "请先点击 Confirm Arrive 再 Done。");
            return;
          }

          const d = getFormData();

          if (!d.date) {
            toast("缺少日期", "请先选择 Date。");
            return;
          }
          if (!d.driverNumber || !d.driverName) {
            toast("缺少司机信息", "请填写 Driver's Number / Name。");
            return;
          }
          if (!d.accountNumber || !d.accountName) {
            toast(
              "缺少客户信息",
              "请搜索并选择客户，或手动填写 Account 字段。",
            );
            return;
          }

          // Mark as done in UI/state
          d.done = true;
          setPill("donePill", true);
          setStatus("已完成");

          // compute remaining for tomorrow autofill
          const baseTdg2 = Number($("tdgVolume")?.value || 0);
          const cal2 = computeRemainingTDG(baseTdg2, getRecords());
          d.remainingVolume = cal2.remaining;

          // enrich record with timing + client id (idempotent sync key)
          d.arrivalTime = arrivalTime || "";
          d.shiftStart = shiftStart || "";
          d.shiftFinish = shiftFinish || "";
          d.completedAt = new Date().toISOString();
          d.clientRecordId = d.clientRecordId || genClientRecordId();

          // Save record locally first (offline-first safety)
          const records = getRecords();
          records.push({ ...d });
          setRecords(records);

          // After adding a record locally, prepare for next customer immediately
          resetAccountFieldsForNextRecord();
          isArrived = false;
          arrivalTime = "";
          renderArrivalUI();
          setPill("donePill", false);
          setPill("arrivePill", false);
          setStatus("Driving");

          // Sync this single record to Supabase (best-effort, non-blocking UX)
          // If it fails (offline/RLS/etc), local record remains; Off Duty will retry sync-all.
          (async () => {
            try {
              await syncRecordToSupabase(d);
              // Mark last record as synced in local storage
              const list2 = getRecords();
              // last item should be this record, but find by clientRecordId to be safe
              const idx = list2.findIndex((r) => r.clientRecordId === d.clientRecordId);
              if (idx >= 0) {
                list2[idx].synced = true;
                list2[idx].syncError = "";
                setRecords(list2);
              }
              toast("已同步", "本次记录已保存到云端数据库。");
            } catch (e) {
              console.warn("syncRecordToSupabase failed:", e);
              const msg = String(e?.message || e || "sync failed");
              // Persist error for troubleshooting / later retry
              const list2 = getRecords();
              const idx = list2.findIndex((r) => r.clientRecordId === d.clientRecordId);
              if (idx >= 0) {
                list2[idx].synced = false;
                list2[idx].syncError = msg;
                setRecords(list2);
              }
              toast("离线/失败", "已保存本地；Off Duty 时会自动补传。");
            }
          })();

          // Rotate cycle (your existing logic)
          rotateWeekCycle();

          // prepare next customer form
          const next = {
            ...d,
            accountNumber: "",
            accountName: "",
            accountAddress: "",
            accountCity: "",
            accountRoute: "",
            deliveredVolume: 0,
            notes: "",
            arrived: false,
            arrivalTime: "",
            done: false,
          };

          setFormData(next);

          // Clear search UI
          if ($("searchBox")) $("searchBox").value = "";
          const resultBox = $("resultBox");
          if (resultBox) {
            resultBox.innerHTML = `
              <h3 style="margin: 0 0 8px 0;">Search result shows here</h3>
              <div class="muted">已保存。请搜索/填写下一个客户。</div>
            `;
          }

          $("accountNumber")?.focus();
        } finally {
          window.__savingDone = false;
        }
      }

      function resetForm() {
        const keepCycle = $("weekCycle")?.value || "1";

        isArrived = false;
        arrivalTime = "";
        shiftStart = "";
        shiftFinish = "";

        setFormData({
          date: "",
          weekCycle: Number(keepCycle),
          arrived: false,
          arrivalTime: "",
          shiftTimeStart: "",
          shiftTimeFinish: "",
          done: false,
        });

        if ($("searchBox")) $("searchBox").value = "";
        const resultBox = $("resultBox");
        if (resultBox) {
          resultBox.innerHTML = `
            <h3 style="margin: 0 0 8px 0;">Search result shows here</h3>
            <div class="muted">已重置。你可以重新搜索客户。</div>
          `;
        }

        toast("已重置", "表单已清空（Week Cycle 保留）。");
      
        saveIndexState();
      }

      function loadDraftIfAny() {
        const raw = localStorage.getItem(LS_DRAFT);
        if (!raw) return;
        try {
          const d = JSON.parse(raw);
          setFormData(d);
          toast("已恢复", "已从本地草稿恢复上次填写内容。");
        } catch {}
      
        saveIndexState();
      }

      // ---------------------------
      // Wire up
      // ---------------------------
      document.addEventListener("DOMContentLoaded", () => {
        function updateTotalKm() {
          const start = Number($("startKm")?.value || 0);
          const end = Number($("endKm")?.value || 0);

          if (!start && !end) {
            $("totalKm").value = "";
            return;
          }

          const total = end - start;
          $("totalKm").value = total >= 0 ? total : "";
        }

        $("startKm")?.addEventListener("input", updateTotalKm);
        $("endKm")?.addEventListener("input", updateTotalKm);
        // ============================
        // Enterprise: Auth gate (single source of truth)
        // ============================
        const sess = window.TDG_AUTH?.requireAuth?.(); // not logged in -> redirect login.html
        if (!sess) return;

        const fillDriverFromSession = (s) => {
          const dn = s.driverNumber || s.username || "";
          const nm = s.displayName || s.username || "";
          if ($("driverNumber")) $("driverNumber").value = dn;
          if ($("driverName")) $("driverName").value = nm;
        };

        fillDriverFromSession(sess);

        

        // Restore index state when coming back from Current Detail
        restoreIndexState();
// Auto-fill TDG Volume from yesterday remaining (per-driver)
        autoLoadVolumeFromYesterday();

        // 按钮事件绑定
        $("btnSeedDemo")?.addEventListener("click", seedDemoCustomers);

        $("btnSearch")?.addEventListener("click", () =>
          renderResults(searchCustomers($("searchBox")?.value)),
        );

        $("searchBox")?.addEventListener("keydown", (e) => {
          if (e.key === "Enter") $("btnSearch")?.click();
        });

        $("btnClearSearch")?.addEventListener("click", () => {
          if ($("searchBox")) $("searchBox").value = "";
          renderResults([]);
        });

        $("btnArrive")?.addEventListener("click", confirmArrive);
        $("btnCheckIn")?.addEventListener("click", checkIn);
        $("btnCheckOut")?.addEventListener("click", checkOut);

        $("btnSaveDraft")?.addEventListener("click", saveDraft);
        $("btnDone")?.addEventListener("click", done);
        $("btnReset")?.addEventListener("click", resetForm);
        $("btnLogout")?.addEventListener("click", logoutFlow);
        $("btnRemoteBackup")?.addEventListener("click", remoteBackupFlow);

        $("btnLoadProfile")?.addEventListener("click", loadFromProfile);
        $("btnLoadCalendar")?.addEventListener("click", loadFromCalendar);
        $("btnLoadYesterday")?.addEventListener("click", loadFromYesterday);

        $("weekCycle")?.addEventListener("change", () => {
          const val = $("weekCycle")?.value;
          if (val) localStorage.setItem(LS_CYCLE, val);
        });

        $("btnToday")?.addEventListener("click", () => {
          saveIndexState();
          window.location.href = "./Current_Detail.html";
        });

        $("btnHistory")?.addEventListener("click", () => {
          window.location.href = "./History_Record.html";
        });

        $("btnGenText")?.addEventListener("click", () => {
          toast("生成文本", "功能开发中");
        });

        // 注册 service worker
        if ("serviceWorker" in navigator) {
          window.addEventListener("load", async () => {
            try {
              await navigator.serviceWorker.register("./sw.js");
            } catch {}
          });
        }


        // Auto-save form fields to sessionStorage (so Back won't lose data)
        [
          "date","vehicleNo","tdgVolume","startKm","endKm","totalKm","weekCycle",
          "accountNumber","accountName","accountAddress","accountCity","accountRoute",
          "deliveredVolume","notes"
        ].forEach((id) => {
          const el = document.getElementById(id);
          if (!el) return;
          el.addEventListener("input", scheduleSaveIndexState, { passive: true });
          el.addEventListener("change", scheduleSaveIndexState, { passive: true });
        });

        // 初始化
        const t = new Date();
        const dateInput = $("date");
        if (dateInput && !dateInput.value) {
          dateInput.value = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, "0")}-${String(t.getDate()).padStart(2, "0")}`;
        }

        ensureDemoProfile();
        loadWeekCycle();
        renderShiftTime();
        renderArrivalUI();
        loadDraftIfAny();

        // Ensure driver fields always follow session (draft must not override)
        fillDriverFromSession(sess);

        // Auto-sync customers from server (best-effort)
        // If offline / not logged in, it will silently keep using localStorage customers.
        syncCustomersFromServer({ silent: true });
      });


      // ---------------------------
      // SessionStorage: index state for back/forward navigation
      // ---------------------------
      const SS_INDEX_STATE = "tdg_index_state_v2";

      function saveIndexState() {
        try {
          const d = getFormData();
          sessionStorage.setItem(SS_INDEX_STATE, JSON.stringify(d));
        } catch {}
      }

      function restoreIndexState() {
        try {
          const raw = sessionStorage.getItem(SS_INDEX_STATE);
          if (!raw) return false;
          const d = JSON.parse(raw);
          if (!d || typeof d !== "object") return false;
          setFormData(d);
          return true;
        } catch {
          return false;
        }
      }

      let __saveIndexTimer = null;
      function scheduleSaveIndexState() {
        clearTimeout(__saveIndexTimer);
        __saveIndexTimer = setTimeout(saveIndexState, 150);
      }

      window.addEventListener("pageshow", () => {
        // Restore again on back/forward cache scenarios
        restoreIndexState();
      });
