/* /js/admin.js  (Refactored: CRUD + Mock API + Hardening) */
(() => {
  "use strict";

  // =========================
  // DOM helpers
  // =========================
  const $ = (id) => document.getElementById(id);
  const on = (el, ev, fn, opts) => el && el.addEventListener(ev, fn, opts);
  const safe = (v) => String(v ?? "").trim();
  const lower = (v) => safe(v).toLowerCase();

  // =========================
  // Basic XSS-safe escaping
  // =========================
  const escapeHtml = (s) =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  // =========================
  // ID / time
  // =========================
  const uid = () =>
    "X" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  const nowIso = () => new Date().toISOString();

  // =========================
  // Auth guard (existing project auth)
  // =========================
  const sess = window.TDG_AUTH?.requireAuth?.({ roles: ["admin"] });
  if (!sess) return;

  $("who").textContent = `当前登录：${sess.displayName || sess.username}（${
    sess.role
  }）`;
  on($("btnLogout"), "click", () => window.TDG_AUTH.logout());

  // =========================
  // Modal
  // =========================
  function openModal(title, bodyHtml, { onClose } = {}) {
    $("modalTitle").textContent = title;
    $("modalBody").innerHTML = bodyHtml;
    $("modalBackdrop").style.display = "flex";
    $("modalBackdrop").setAttribute("aria-hidden", "false");

    const close = () => {
      $("modalBackdrop").style.display = "none";
      $("modalBackdrop").setAttribute("aria-hidden", "true");
      $("modalBody").innerHTML = "";
      onClose && onClose();
    };

    $("modalBackdrop").onclick = (e) => {
      if (e.target === $("modalBackdrop")) close();
    };

    const esc = (ev) => {
      if (ev.key === "Escape") {
        document.removeEventListener("keydown", esc);
        close();
      }
    };
    document.addEventListener("keydown", esc);

    return { close };
  }

  // =========================
  // Validation / normalization
  // =========================
  const Rules = {
    // Driver Number becomes the unique account key.
    driverNumberKey: (v) => /^[A-Za-z0-9._-]{2,32}$/.test(v),
    displayName: (v) => v.length <= 60,
    role: (v) => ["admin", "driver", "viewer"].includes(v),
  };

  function assertOrThrow(cond, msg) {
    if (!cond) throw new Error(msg);
  }

  // =========================
  // Mock API Layer (swap later for backend fetch)
  // =========================
  const StorageKeys = {
    customers: "tdg_customers_demo_v2",
  };
// =========================
// Customers pagination
// =========================
let custPage = 1;          // 当前页
const CUST_PAGE_SIZE = 5;  // 每页 5 条

  const Api = {
    users: {
      async list() {
        await window.TDG_AUTH.ensureSeedAdmin();
        const list = window.TDG_AUTH.getUsers() || [];
        return sanitizeUsers(list);
      },

      // payload expects: driverNumber, displayName, role, isActive, mustChangePassword, password
      async create(payload) {
        await window.TDG_AUTH.ensureSeedAdmin();
        const users = window.TDG_AUTH.getUsers() || [];

        const u = normalizeUserPayload(payload, { mode: "create" });

        // driverNumber is the unique key => username = driverNumber
        const username = u.driverNumber;

        const clash = users.find((x) => lower(x.username) === lower(username));
        assertOrThrow(!clash, "Driver Number 已存在");

        const passwordHash = await window.TDG_AUTH.sha256(u.password);
        const record = {
          id: uid(),
          username, // internal storage still uses username field
          displayName: u.displayName,
          role: u.role,
          driverNumber: u.driverNumber,
          phone: "",
          email: "",
          isActive: u.isActive,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          passwordHash,
          mustChangePassword: !!u.mustChangePassword,
          lastLoginAt: "",
        };

        // Hardening: do not allow creating admin silently
        if (record.role === "admin") {
          assertOrThrow(
            confirm("你正在创建 admin 用户，确定继续？"),
            "已取消创建 admin"
          );
        }

        users.push(record);
        window.TDG_AUTH.setUsers(users);
        return sanitizeUsers([record])[0];
      },

      // patch expects: driverNumber, displayName, role, isActive, mustChangePassword, password(optional)
      async update(id, patch) {
        await window.TDG_AUTH.ensureSeedAdmin();
        const users = window.TDG_AUTH.getUsers() || [];
        const idx = users.findIndex((x) => x.id === id);
        assertOrThrow(idx >= 0, "用户不存在");

        const current = users[idx];

        // Hardening: keep default admin protected
        if (current.username === "admin") {
          const allowed = ["displayName", "isActive", "password", "mustChangePassword"];
          for (const k of Object.keys(patch)) {
            assertOrThrow(
              allowed.includes(k),
              "默认 admin 仅允许修改：姓名/状态/密码"
            );
          }
        }

        const upd = normalizeUserPayload(
          { ...current, ...patch },
          { mode: "update", current }
        );

        // driverNumber is unique key => username mirrors driverNumber (except default admin)
        let nextUsername = current.username;
        if (current.username !== "admin") {
          nextUsername = upd.driverNumber;
          if (lower(nextUsername) !== lower(current.username)) {
            const clash = users.find(
              (x) => x.id !== id && lower(x.username) === lower(nextUsername)
            );
            assertOrThrow(!clash, "Driver Number 已存在");
          }
        }

        const next = { ...current };
        next.username = nextUsername;
        next.driverNumber = upd.driverNumber;
        next.displayName = upd.displayName;
        next.role = upd.role;
        next.isActive = upd.isActive;
        next.mustChangePassword = !!upd.mustChangePassword;
        next.updatedAt = nowIso();

        if (upd.password) {
          next.passwordHash = await window.TDG_AUTH.sha256(upd.password);
        }

        // Hardening: avoid disabling the last active admin
        if (next.role === "admin" && next.isActive === false) {
          const adminsActive = users.filter(
            (u) => u.id !== id && u.role === "admin" && u.isActive
          );
          assertOrThrow(
            adminsActive.length > 0 || confirm("这是最后一个启用的 admin，仍要停用吗？"),
            "已取消停用最后一个 admin"
          );
        }

        users[idx] = next;
        window.TDG_AUTH.setUsers(users);
        return sanitizeUsers([next])[0];
      },

      async remove(id) {
        await window.TDG_AUTH.ensureSeedAdmin();
        const users = window.TDG_AUTH.getUsers() || [];
        const u = users.find((x) => x.id === id);
        assertOrThrow(!!u, "用户不存在");

        assertOrThrow(u.username !== "admin", "默认 admin 不允许删除");

        if (u.role === "admin" && u.isActive) {
          const others = users.filter(
            (x) => x.id !== id && x.role === "admin" && x.isActive
          );
          assertOrThrow(others.length > 0, "不能删除最后一个启用的 admin");
        }

        const next = users.filter((x) => x.id !== id);
        window.TDG_AUTH.setUsers(next);
        return true;
      },
    },

    customers: {
      list() {
        return sanitizeCustomers(loadCustomers());
      },
      create(payload) {
        const list = loadCustomers();
        const c = normalizeCustomerPayload(payload);

        assertOrThrow(
          !list.some((x) => safe(x.accountNumber) === c.accountNumber),
          "Account Number 已存在"
        );

        list.push(c);
        saveCustomers(list);
        return sanitizeCustomers([c])[0];
      },
      update(index, patch) {
        const list = loadCustomers();
        assertOrThrow(index >= 0 && index < list.length, "客户不存在");

        const current = list[index];
        const next = normalizeCustomerPayload({ ...current, ...patch });

        assertOrThrow(
          !list.some(
            (x, i) => i !== index && safe(x.accountNumber) === next.accountNumber
          ),
          "Account Number 已存在"
        );

        list[index] = next;
        saveCustomers(list);
        return sanitizeCustomers([next])[0];
      },
      remove(index) {
        const list = loadCustomers();
        assertOrThrow(index >= 0 && index < list.length, "客户不存在");
        list.splice(index, 1);
        saveCustomers(list);
        return true;
      },
      importFromCsvText(csvText) {
        const rows = parseCsv(csvText);
        assertOrThrow(rows.length > 0, "CSV 没有数据");

        const mapped = rows
  .map((r) => ({
    accountNumber: safe(
      r.accountNumber ??
        r.accountNo ??
        r.no ??
        r.Position ??                 // ✅ 你的CSV常用：Position
        r["Account Number"] ??
        r["AccountNo"] ??
        ""
    ),
    accountName: safe(
      r.accountName ??
        r.name ??
        r["Customer Name"] ??         // ✅ 你的CSV常用：Customer Name
        r["Account Name"] ??
        ""
    ),
    accountAddress: safe(
      r.accountAddress ??
        r.address ??
        r.Address ??                  // ✅ 你的CSV常用：Address
        r["Account Address"] ??
        ""
    ),
    city: safe(
      r.city ??
        r.City ??                     // ✅ 你的CSV常用：City
        ""
    ),
    route: safe(
      r.route ??
        r.Route ??                    // ✅ 你的CSV常用：Route
        ""
    ),
  }))
  .filter((x) => x.accountNumber && x.accountName);

        assertOrThrow(
          mapped.length > 0,
          "CSV 缺少必要字段（Account Number / Name）"
        );

        const existing = loadCustomers();
        const byNo = new Map(existing.map((c) => [safe(c.accountNumber), c]));
        for (const c of mapped) byNo.set(c.accountNumber, c);

        const merged = Array.from(byNo.values()).sort((a, b) =>
          safe(a.accountNumber).localeCompare(safe(b.accountNumber))
        );
        saveCustomers(merged);
        return merged.length;
      },
    },
  };

  // =========================
  // Storage helpers (customers)
  // =========================
  function loadCustomers() {
    try {
      return JSON.parse(localStorage.getItem(StorageKeys.customers) || "[]");
    } catch {
      return [];
    }
  }
  function saveCustomers(list) {
    localStorage.setItem(StorageKeys.customers, JSON.stringify(list));
  }

  // =========================
  // Sanitizers (defensive rendering)
  // =========================
  function sanitizeUsers(list) {
    return (Array.isArray(list) ? list : []).map((u) => ({
      id: safe(u.id),
      // internal field kept but not shown
      username: safe(u.username),
      // Driver Number is the primary shown key
      driverNumber: safe(u.driverNumber || u.username),
      displayName: safe(u.displayName),
      role: Rules.role(safe(u.role)) ? safe(u.role) : "viewer",
      isActive: !!u.isActive,
      mustChangePassword: !!u.mustChangePassword,
      lastLoginAt: safe(u.lastLoginAt),
      createdAt: safe(u.createdAt),
      updatedAt: safe(u.updatedAt),
    }));
  }

function sanitizeCustomers(list) {
  return (Array.isArray(list) ? list : []).map((c) => ({
    accountNumber: safe(c.accountNumber),
    accountName: safe(c.accountName),
    accountAddress: safe(c.accountAddress),
    city: safe(c.city),
    route: safe(c.route),
  }));
}

  // =========================
  // Normalizers
  // =========================
  function normalizeUserPayload(payload, { mode, current } = {}) {
    const driverNumber = safe(payload.driverNumber || payload.username); // backward compat
    const displayName = safe(payload.displayName);
    const role = safe(payload.role || "driver");
    const isActive = payload.isActive === false ? false : true;
    const mustChangePassword = !!payload.mustChangePassword;
    const password = safe(payload.password);

    // default admin: allow empty driverNumberKey check if current is admin
    if (current?.username === "admin") {
      // admin is special; driverNumber can be anything but we still keep it trimmed.
    } else {
      assertOrThrow(driverNumber, "Driver Number 不能为空");
      assertOrThrow(
        Rules.driverNumberKey(driverNumber),
        "Driver Number 格式不合法（2-32位，字母数字._-）"
      );
    }

    assertOrThrow(Rules.displayName(displayName), "Display Name 太长");
    assertOrThrow(Rules.role(role), "Role 不合法");

    if (mode === "create") {
      assertOrThrow(password, "初始密码不能为空");
      assertOrThrow(password.length >= 6, "密码至少 6 位");
    }
    if (mode === "update") {
      if (password) assertOrThrow(password.length >= 6, "密码至少 6 位");
    }

    return {
      driverNumber,
      displayName,
      role,
      isActive,
      mustChangePassword,
      password,
    };
  }

  function normalizeCustomerPayload(payload) {
    const accountNumber = safe(payload.accountNumber);
    const accountName = safe(payload.accountName);
    const accountAddress = safe(payload.accountAddress);
    const city = safe(payload.city);
    const route = safe(payload.route);

    assertOrThrow(city.length <= 60, "City 太长");
    assertOrThrow(route.length <= 60, "Route 太长");

    return { accountNumber, accountName, accountAddress, city, route };
  }

  // =========================
  // CSV parser (simple, supports quoted fields)
  // =========================
  function parseCsv(text) {
    const t = String(text ?? "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n")
      .trim();
    if (!t) return [];

    const lines = [];
    let cur = "";
    let inQ = false;
    for (let i = 0; i < t.length; i++) {
      const ch = t[i];
      if (ch === '"') {
        if (inQ && t[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQ = !inQ;
        }
      } else if (ch === "\n" && !inQ) {
        lines.push(cur);
        cur = "";
      } else {
        cur += ch;
      }
    }
    if (cur) lines.push(cur);

    const splitRow = (row) => {
      const out = [];
      let s = "";
      let q = false;
      for (let i = 0; i < row.length; i++) {
        const ch = row[i];
        if (ch === '"') {
          if (q && row[i + 1] === '"') {
            s += '"';
            i++;
          } else q = !q;
        } else if (ch === "," && !q) {
          out.push(s);
          s = "";
        } else s += ch;
      }
      out.push(s);
      return out.map((x) => x.trim());
    };

    const header = splitRow(lines[0]).map((h) => h.replace(/^\uFEFF/, "").trim());
    const rows = [];

    for (let i = 1; i < lines.length; i++) {
      const cols = splitRow(lines[i]);
      if (cols.every((c) => !c)) continue;
      const obj = {};
      for (let j = 0; j < header.length; j++) obj[header[j]] = cols[j] ?? "";
      rows.push(obj);
    }
    return rows;
  }

  // =========================
  // Tabs
  // =========================
  document.querySelectorAll(".tab").forEach((t) => {
    on(
      t,
      "click",
      () => {
        document
          .querySelectorAll(".tab")
          .forEach((x) => x.classList.remove("active"));
        t.classList.add("active");
        const tab = t.getAttribute("data-tab");
        $("panel-users").style.display = tab === "users" ? "" : "none";
        $("panel-customers").style.display = tab === "customers" ? "" : "none";
        $("panel-tools").style.display = tab === "tools" ? "" : "none";
        renderAll();
      },
      { passive: true }
    );
  });

  // =========================
  // USERS: Render + CRUD UI
  // =========================
  async function renderUsers() {
    const wrap = $("usersTableWrap");
    if (!wrap) return;

    let users = [];
    try {
      const q = lower($("userSearch")?.value);
      users = await Api.users.list();
      if (q) {
        users = users.filter(
          (u) =>
            lower(u.driverNumber).includes(q) ||
            lower(u.displayName).includes(q)
        );
      }
      users.sort((a, b) =>
        safe(a.driverNumber).localeCompare(safe(b.driverNumber))
      );
    } catch (e) {
      wrap.innerHTML = `<div class="empty">加载失败：${escapeHtml(
        e.message || "error"
      )}</div>`;
      return;
    }

    const rows = users
      .map((u) => {
        const roleChip = `<span class="chip">${escapeHtml(u.role)}</span>`;
        const activeChip = `<span class="chip">${
          u.isActive ? "active" : "disabled"
        }</span>`;
        const must = u.mustChangePassword
          ? `<span class="chip">must change pwd</span>`
          : "";
        const lastLogin = u.lastLoginAt
          ? escapeHtml(u.lastLoginAt.slice(0, 19).replace("T", " "))
          : "-";

        return `
          <tr>
            <td>
              <div style="font-weight:800">${escapeHtml(u.driverNumber)}</div>
              <div style="opacity:.75;margin-top:6px">${escapeHtml(
                u.displayName || ""
              )}</div>
            </td>
            <td>${roleChip} ${activeChip} ${must}</td>
            <td>
              <div class="muted">Last login: ${lastLogin}</div>
            </td>
            <td style="white-space:nowrap">
              <button class="btn secondary" data-act="user-edit" data-id="${escapeHtml(
                u.id
              )}" type="button">编辑</button>
              <button class="btn warn" data-act="user-del" data-id="${escapeHtml(
                u.id
              )}" type="button">删除</button>
            </td>
          </tr>
        `;
      })
      .join("");

    wrap.innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th>Driver Number</th><th>角色/状态</th><th>登录</th><th>操作</th>
          </tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="4">无数据</td></tr>`}</tbody>
      </table>
    `;
  }

  function userFormHtml({ mode, data }) {
    const u = data || {};
    const isEdit = mode === "edit";
    const lockAdmin = u.username === "admin"; // default admin hardening

    return `
      <div class="row2">
        <div>
          <label>Driver Number（User Name）</label>
          <input id="f_driverNumber" value="${escapeHtml(u.driverNumber || u.username || "")}"
            ${lockAdmin ? "disabled" : ""}  />
        </div>
        <div>
          <label>Display Name（Full Name）</label>
          <input id="f_displayName" value="${escapeHtml(u.displayName || "")}"  />
        </div>
      </div>

      <div class="row2" style="margin-top:10px">
        <div>
          <label>Role</label>
          <select id="f_role" ${lockAdmin ? "disabled" : ""}>
            <option value="driver" ${u.role === "driver" ? "selected" : ""}>driver</option>
            <option value="viewer" ${u.role === "viewer" ? "selected" : ""}>viewer</option>
            <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
          </select>
        </div>
        <div>
          <label>Status</label>
          <select id="f_active">
            <option value="1" ${u.isActive !== false ? "selected" : ""}>active</option>
            <option value="0" ${u.isActive === false ? "selected" : ""}>disabled</option>
          </select>
        </div>
      </div>

      <div class="row2" style="margin-top:10px">
        <div>
          <label>${isEdit ? "New Password（留空不改）" : "Initial Password"}</label>
          <input id="f_password" type="password" placeholder="${
            isEdit ? "留空不修改" : "至少 6 位"
          }" />
        </div>
        <div style="display:flex;align-items:end">
          <label style="display:flex;align-items:center;gap:8px;margin:0">
            <input id="f_mustChange" type="checkbox" ${
              u.mustChangePassword ? "checked" : ""
            } />
            must change password on next login
          </label>
        </div>
      </div>

      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">Cancel</button>
        <button class="btn ok" id="btnSave" type="button">${
          isEdit ? "Save" : "Add"
        }</button>
      </div>
    `;
  }

  async function openCreateUser() {
    const modal = openModal("Creat User", userFormHtml({ mode: "create", data: {} }), {
      onClose: renderAll,
    });

    $("btnCancel").onclick = () => modal.close();
    $("btnSave").onclick = async () => {
      try {
        const payload = {
          driverNumber: safe($("f_driverNumber").value),
          displayName: safe($("f_displayName").value),
          role: $("f_role").value,
          isActive: $("f_active").value === "1",
          mustChangePassword: $("f_mustChange").checked,
          password: safe($("f_password").value),
        };
        await Api.users.create(payload);
        modal.close();
        alert("已创建");
      } catch (e) {
        alert(e.message || "创建失败");
      }
    };
  }

  async function openEditUser(id) {
    let users;
    try {
      users = await Api.users.list();
    } catch {
      return alert("加载用户失败");
    }
    const u = users.find((x) => x.id === id);
    if (!u) return alert("用户不存在");

    const modal = openModal("编辑用户", userFormHtml({ mode: "edit", data: u }), {
      onClose: renderAll,
    });

    $("btnCancel").onclick = () => modal.close();
    $("btnSave").onclick = async () => {
      try {
        const patch = {
          driverNumber: safe($("f_driverNumber").value),
          displayName: safe($("f_displayName").value),
          role: $("f_role").value,
          isActive: $("f_active").value === "1",
          mustChangePassword: $("f_mustChange").checked,
          password: safe($("f_password").value), // optional
        };
        await Api.users.update(id, patch);
        modal.close();
        alert("已保存");
      } catch (e) {
        alert(e.message || "保存失败");
      }
    };
  }

  async function deleteUser(id) {
    try {
      const users = await Api.users.list();
      const u = users.find((x) => x.id === id);
      if (!u) return alert("用户不存在");
      if (!confirm(`确定删除用户：${u.driverNumber} ?`)) return;

      await Api.users.remove(id);
      alert("已删除");
      renderAll();
    } catch (e) {
      alert(e.message || "删除失败");
    }
  }

  // =========================
  // CUSTOMERS: Render + CRUD UI
  // =========================
  function renderCustomers() {
    const wrap = $("customersTableWrap");
    if (!wrap) return;

    let list;
    try {
      list = Api.customers.list();
    } catch (e) {
      wrap.innerHTML = `<div class="empty">加载失败：${escapeHtml(
        e.message || "error"
      )}</div>`;
      return;
    }

    const q = lower($("custSearch")?.value);
    let filtered = list;
    if (q) {
      filtered = list.filter(
        (c) =>
          lower(c.accountNumber).includes(q) ||
          lower(c.accountName).includes(q) ||
          lower(c.accountAddress).includes(q) ||
          lower(c.city).includes(q) ||
          lower(c.route).includes(q)
      );
    }

    const all = filtered
      .slice()
      .sort((a, b) => safe(a.accountNumber).localeCompare(safe(b.accountNumber)));

    if (!all.length) {
      wrap.innerHTML = `<div class="empty">无数据</div>`;
      return;
    }

    const base = Api.customers.list();
    const idxMap = new Map(base.map((c, i) => [safe(c.accountNumber), i]));

const total = all.length;
const totalPages = Math.max(1, Math.ceil(total / CUST_PAGE_SIZE));
custPage = Math.min(Math.max(1, custPage), totalPages);

const start = (custPage - 1) * CUST_PAGE_SIZE;
const pageItems = all.slice(start, start + CUST_PAGE_SIZE);

const rows = pageItems
  .map((c) => {
    const idx = idxMap.get(safe(c.accountNumber));
    return `
      <tr>
        <td>
          <div style="font-weight:800">${escapeHtml(c.accountNumber)}</div>
          <div class="muted" style="margin-top:6px">${escapeHtml(c.accountName)}</div>
        </td>
        <td class="muted">${escapeHtml(c.accountAddress || "")}</td>
        <td class="muted">${escapeHtml(c.city || "")}</td>
        <td class="muted">${escapeHtml(c.route || "")}</td>
        <td style="white-space:nowrap">
          <button class="btn secondary" data-act="cust-edit" data-idx="${idx}" type="button">编辑</button>
          <button class="btn warn" data-act="cust-del" data-idx="${idx}" type="button">删除</button>
        </td>
      </tr>
    `;
  })
  .join("");

    wrap.innerHTML = `
  <table class="table">
    <thead>
      <tr><th>Account</th><th>Address</th><th>City</th><th>Route</th><th>操作</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>

  <div class="grid-actions" style="justify-content:flex-end; margin-top:10px">
    <span class="muted" style="margin-right:auto">
      Showing ${start + 1}-${Math.min(start + CUST_PAGE_SIZE, total)} of ${total}
    </span>

    <button class="btn secondary" type="button" data-act="cust-page-prev" ${custPage === 1 ? "disabled" : ""}>Prev</button>
    <span class="chip">Page ${custPage} / ${totalPages}</span>
    <button class="btn secondary" type="button" data-act="cust-page-next" ${custPage === totalPages ? "disabled" : ""}>Next</button>
  </div>
`;
  }

  function customerFormHtml({ mode, data }) {
    const c = data || {};
    const isEdit = mode === "edit";
    return `
      <div class="row2">
        <div>
          <label>Account Number</label>
          <input id="c_no" value="${escapeHtml(c.accountNumber || "")}" placeholder="1008" />
        </div>
        <div>
          <label>Account Name</label>
          <input id="c_name" value="${escapeHtml(
            c.accountName || ""
          )}" placeholder="Customer Name" />
        </div>
      </div>
      <div style="margin-top:10px">
        <label>Account Address</label>
        <input id="c_addr" value="${escapeHtml(
          c.accountAddress || ""
        )}" placeholder="Street, City, Province" />
      </div>
       <div class="row2" style="margin-top:10px">
       <div>
      <label>City</label>
      <input id="c_city" value="${escapeHtml(c.city || "")}" placeholder="Winnipeg" />
      </div>
      <div>
    <label>Route</label>
    <input id="c_route" value="${escapeHtml(c.route || "")}" placeholder="R-01" />
  </div>
</div>
      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">Cancel</button>
        <button class="btn ok" id="btnSave" type="button">${
          isEdit ? "保存" : "创建"
        }</button>
      </div>
    `;
  }

  function openCreateCustomer() {
    const modal = openModal(
      "新增客户",
      customerFormHtml({ mode: "create", data: {} }),
      { onClose: renderAll }
    );
    $("btnCancel").onclick = () => modal.close();
    $("btnSave").onclick = () => {
      try {
       const payload = {
       accountNumber: safe($("c_no").value),
       accountName: safe($("c_name").value),
       accountAddress: safe($("c_addr").value),
       city: safe($("c_city").value),
       route: safe($("c_route").value),
    };
        Api.customers.create(payload);
        modal.close();
        alert("已创建");
      } catch (e) {
        alert(e.message || "创建失败");
      }
    };
  }

  function openEditCustomer(index) {
    const list = Api.customers.list();
    const c = list[index];
    if (!c) return alert("客户不存在");

    const modal = openModal(
      "编辑客户",
      customerFormHtml({ mode: "edit", data: c }),
      { onClose: renderAll }
    );
    $("btnCancel").onclick = () => modal.close();
    $("btnSave").onclick = () => {
      try {
        const patch = {
          accountNumber: safe($("c_no").value),
          accountName: safe($("c_name").value),
          accountAddress: safe($("c_addr").value),
          city: safe($("c_city").value),
          route: safe($("c_route").value),
        };
        Api.customers.update(index, patch);
        modal.close();
        alert("已保存");
      } catch (e) {
        alert(e.message || "保存失败");
      }
    };
  }

  function deleteCustomer(index) {
    const list = Api.customers.list();
    const c = list[index];
    if (!c) return alert("客户不存在");
    if (!confirm(`确定删除客户：${c.accountNumber} / ${c.accountName} ?`))
      return;
    try {
      Api.customers.remove(index);
      alert("已删除");
      renderAll();
    } catch (e) {
      alert(e.message || "删除失败");
    }
  }

  // =========================
  // Event wiring
  // =========================
  on($("userSearch"), "input", () => renderUsers(), { passive: true });
  on($("custSearch"), "input", () => renderCustomers(), { passive: true });

  on($("btnAddUser"), "click", () => openCreateUser(), { passive: true });
  on($("btnAddCustomer"), "click", () => openCreateCustomer(), { passive: true });

  on($("importCustomersCsv"), "change", async (e) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    try {
      const text = await f.text();
      const n = Api.customers.importFromCsvText(text);
      alert(`导入成功（合并后共 ${n} 条）`);
      renderCustomers();
    } catch (err) {
      alert(err.message || "CSV 导入失败");
    }
  });

  on(document, "click", (e) => {
    const btn = e.target?.closest?.("button[data-act]");
    if (!btn) return;

    const act = btn.getAttribute("data-act");
      // ✅ 分页按钮（加在这里）
  if (act === "cust-page-prev") {
    custPage = Math.max(1, custPage - 1);
    return renderCustomers();
  }
  if (act === "cust-page-next") {
    custPage = custPage + 1;
    return renderCustomers();
  }
  if (act === "user-edit") return openEditUser(btn.getAttribute("data-id"));
  if (act === "user-del") return deleteUser(btn.getAttribute("data-id"));
  if (act === "cust-edit")
    return openEditCustomer(Number(btn.getAttribute("data-idx")));
  if (act === "cust-del")
    return deleteCustomer(Number(btn.getAttribute("data-idx")));
  });

  on($("btnDangerResetAll"), "click", () => {
    if (!confirm("⚠️确定清空所有本地数据？（不可恢复）")) return;
    localStorage.clear();
    sessionStorage.clear();
    alert("已清空。将返回登录页。");
    window.location.href = "./login.html";
  });

  function renderAll() {
    renderUsers();
    renderCustomers();
  }

  renderAll();
})();