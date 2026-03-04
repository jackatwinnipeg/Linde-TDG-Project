/* /js/admin.js */
(() => {
  const $ = (id) => document.getElementById(id);

  const LS_CUSTOMERS = "tdg_customers_demo_v2";

  const uid = () => "X" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  const nowIso = () => new Date().toISOString();
  const safe = (s) => String(s ?? "").trim();

  const sess = window.TDG_AUTH.requireAuth({ roles: ["admin"] });
  if (!sess) return;
  $("who").textContent = `当前登录：${sess.displayName || sess.username}（${sess.role}）`;

  $("btnLogout").addEventListener("click", () => window.TDG_AUTH.logout());

  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      const tab = t.getAttribute("data-tab");
      $("panel-users").style.display = tab === "users" ? "" : "none";
      $("panel-customers").style.display = tab === "customers" ? "" : "none";
      $("panel-tools").style.display = tab === "tools" ? "" : "none";
      renderAll();
    }, { passive: true });
  });

  function getCustomers() {
    try { return JSON.parse(localStorage.getItem(LS_CUSTOMERS) || "[]"); }
    catch { return []; }
  }
  function setCustomers(list) { localStorage.setItem(LS_CUSTOMERS, JSON.stringify(list)); }

  function openModal(title, bodyHtml, { onClose } = {}) {
    $("modalTitle").textContent = title;
    $("modalBody").innerHTML = bodyHtml;
    $("modalBackdrop").style.display = "flex";
    $("modalBackdrop").setAttribute("aria-hidden", "false");

    const close = () => {
      $("modalBackdrop").style.display = "none";
      $("modalBackdrop").setAttribute("aria-hidden", "true");
      $("modalBody").innerHTML = "";
      if (onClose) onClose();
    };

    $("modalBackdrop").onclick = (e) => { if (e.target === $("modalBackdrop")) close(); };
    document.addEventListener("keydown", function esc(ev){
      if (ev.key === "Escape") {
        document.removeEventListener("keydown", esc);
        close();
      }
    });

    return { close };
  }
  function field(id) { return document.getElementById(id); }

  async function renderUsers() {
    await window.TDG_AUTH.ensureSeedAdmin();
    const q = safe($("userSearch").value).toLowerCase();
    const users = window.TDG_AUTH.getUsers()
      .filter((u) => {
        if (!q) return true;
        return (
          (u.username || "").toLowerCase().includes(q) ||
          (u.displayName || "").toLowerCase().includes(q) ||
          (u.driverNumber || "").toLowerCase().includes(q)
        );
      })
      .sort((a,b) => (a.username||"").localeCompare(b.username||""));

    const rows = users.map((u) => {
      const roleChip = `<span class="chip">${u.role}</span>`;
      const activeChip = `<span class="chip">${u.isActive ? "active" : "disabled"}</span>`;
      const must = u.mustChangePassword ? `<span class="chip">must change pwd</span>` : "";

      return `
        <tr>
          <td>
            <div style="font-weight:800">${escapeHtml(u.username)}</div>
            <div style="opacity:.75;margin-top:6px">${escapeHtml(u.displayName || "")}</div>
          </td>
          <td>${roleChip} ${activeChip} ${must}</td>
          <td>
            <div class="muted">Driver#: ${escapeHtml(u.driverNumber || "-")}</div>
            <div class="muted">Vehicle: ${escapeHtml(u.vehicleNo || "-")}</div>
          </td>
          <td>
            <div class="muted">Last login: ${u.lastLoginAt ? escapeHtml(u.lastLoginAt.slice(0,19).replace("T"," ")) : "-"}</div>
          </td>
          <td style="white-space:nowrap">
            <button class="btn secondary" data-edit-user="${u.id}" type="button">编辑</button>
            <button class="btn warn" data-del-user="${u.id}" type="button">删除</button>
          </td>
        </tr>
      `;
    }).join("");

    $("usersTableWrap").innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th>账号</th><th>角色/状态</th><th>司机信息</th><th>登录</th><th>操作</th>
          </tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="5">无数据</td></tr>`}</tbody>
      </table>
    `;

    document.querySelectorAll("[data-edit-user]").forEach((btn) => {
      btn.addEventListener("click", () => editUser(btn.getAttribute("data-edit-user")), { passive: true });
    });
    document.querySelectorAll("[data-del-user]").forEach((btn) => {
      btn.addEventListener("click", () => deleteUser(btn.getAttribute("data-del-user")), { passive: true });
    });
  }

  async function editUser(userId) {
    await window.TDG_AUTH.ensureSeedAdmin();
    const users = window.TDG_AUTH.getUsers();
    const u = users.find((x) => x.id === userId);
    if (!u) return alert("用户不存在");

    const html = `
      <div class="row2">
        <div>
          <label>Username</label>
          <input id="u_username" value="${escapeHtml(u.username)}" />
        </div>
        <div>
          <label>Display Name</label>
          <input id="u_displayName" value="${escapeHtml(u.displayName || "")}" />
        </div>
      </div>

      <div class="row3" style="margin-top:10px">
        <div>
          <label>Role</label>
          <select id="u_role">
            <option value="admin" ${u.role==="admin"?"selected":""}>admin</option>
            <option value="driver" ${u.role==="driver"?"selected":""}>driver</option>
            <option value="viewer" ${u.role==="viewer"?"selected":""}>viewer</option>
          </select>
        </div>
        <div>
          <label>Driver Number</label>
          <input id="u_driverNumber" value="${escapeHtml(u.driverNumber || "")}" placeholder="D-001" />
        </div>
        <div>
          <label>Vehicle No</label>
          <input id="u_vehicleNo" value="${escapeHtml(u.vehicleNo || "")}" placeholder="VH-102" />
        </div>
      </div>

      <div class="row2" style="margin-top:10px">
        <div>
          <label>Email</label>
          <input id="u_email" value="${escapeHtml(u.email || "")}" placeholder="name@example.com" />
        </div>
        <div>
          <label>Phone</label>
          <input id="u_phone" value="${escapeHtml(u.phone || "")}" placeholder="+1 ..." />
        </div>
      </div>

      <div class="row2" style="margin-top:10px">
        <div>
          <label>Status</label>
          <select id="u_active">
            <option value="1" ${u.isActive ? "selected":""}>active</option>
            <option value="0" ${!u.isActive ? "selected":""}>disabled</option>
          </select>
        </div>
        <div>
          <label>Reset Password</label>
          <input id="u_newpwd" type="password" placeholder="留空则不修改" />
        </div>
      </div>

      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">取消</button>
        <button class="btn ok" id="btnSave" type="button">保存</button>
      </div>
    `;

    const modal = openModal("编辑用户", html, { onClose: renderAll });

    field("btnCancel").onclick = () => modal.close();
    field("btnSave").onclick = async () => {
      const username = safe(field("u_username").value);
      if (!username) return alert("Username 不能为空");

      const lower = username.toLowerCase();
      const clash = users.find((x) => x.id !== u.id && (x.username || "").toLowerCase() === lower);
      if (clash) return alert("Username 已存在");

      u.username = username;
      u.displayName = safe(field("u_displayName").value);
      u.role = field("u_role").value;
      u.driverNumber = safe(field("u_driverNumber").value);
      u.vehicleNo = safe(field("u_vehicleNo").value);
      u.email = safe(field("u_email").value);
      u.phone = safe(field("u_phone").value);
      u.isActive = field("u_active").value === "1";
      u.updatedAt = nowIso();

      const newPwd = safe(field("u_newpwd").value);
      if (newPwd) {
        u.passwordHash = await window.TDG_AUTH.sha256(newPwd);
        u.mustChangePassword = false;
      }

      window.TDG_AUTH.setUsers(users);
      modal.close();
      alert("已保存");
    };
  }

  async function addUser() {
    await window.TDG_AUTH.ensureSeedAdmin();
    const users = window.TDG_AUTH.getUsers();

    const html = `
      <div class="row2">
        <div>
          <label>Username</label>
          <input id="nu_username" placeholder="driver01" />
        </div>
        <div>
          <label>Display Name</label>
          <input id="nu_displayName" placeholder="Penny" />
        </div>
      </div>

      <div class="row3" style="margin-top:10px">
        <div>
          <label>Role</label>
          <select id="nu_role">
            <option value="driver">driver</option>
            <option value="viewer">viewer</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <div>
          <label>Driver Number</label>
          <input id="nu_driverNumber" placeholder="D-001" />
        </div>
        <div>
          <label>Vehicle No</label>
          <input id="nu_vehicleNo" placeholder="VH-102" />
        </div>
      </div>

      <div class="row2" style="margin-top:10px">
        <div>
          <label>Initial Password</label>
          <input id="nu_pwd" type="password" placeholder="建议强密码" />
        </div>
        <div>
          <label>Status</label>
          <select id="nu_active">
            <option value="1">active</option>
            <option value="0">disabled</option>
          </select>
        </div>
      </div>

      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">取消</button>
        <button class="btn ok" id="btnCreate" type="button">创建</button>
      </div>
    `;

    const modal = openModal("新增用户", html, { onClose: renderAll });
    field("btnCancel").onclick = () => modal.close();
    field("btnCreate").onclick = async () => {
      const username = safe(field("nu_username").value);
      const pwd = safe(field("nu_pwd").value);
      if (!username) return alert("Username 不能为空");
      if (!pwd) return alert("初始密码不能为空");

      const clash = users.find((x) => (x.username || "").toLowerCase() === username.toLowerCase());
      if (clash) return alert("Username 已存在");

      users.push({
        id: uid(),
        username,
        displayName: safe(field("nu_displayName").value),
        role: field("nu_role").value,
        driverNumber: safe(field("nu_driverNumber").value),
        vehicleNo: safe(field("nu_vehicleNo").value),
        phone: "",
        email: "",
        isActive: field("nu_active").value === "1",
        createdAt: nowIso(),
        updatedAt: nowIso(),
        passwordHash: await window.TDG_AUTH.sha256(pwd),
        mustChangePassword: false,
        lastLoginAt: "",
      });

      window.TDG_AUTH.setUsers(users);
      modal.close();
      alert("已创建");
    };
  }

  async function deleteUser(userId) {
    await window.TDG_AUTH.ensureSeedAdmin();
    const users = window.TDG_AUTH.getUsers();
    const u = users.find((x) => x.id === userId);
    if (!u) return;

    if (u.username === "admin") {
      return alert("默认 admin 不允许删除（可改密码/停用）");
    }
    if (!confirm(`确定删除用户：${u.username} ?`)) return;

    const next = users.filter((x) => x.id !== userId);
    window.TDG_AUTH.setUsers(next);
    renderAll();
  }

  function exportJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function readJsonFile(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => {
        try { resolve(JSON.parse(fr.result)); } catch (e) { reject(e); }
      };
      fr.onerror = reject;
      fr.readAsText(file);
    });
  }

  function seedCustomersFromYourDemo() {
    const customers = [
      { accountNumber: "1001", accountName: "Manitoba Hydro - South Station", accountAddress: "123 Example St, Winnipeg, MB", shippingInfo: "Dock 3 / 9:00-11:00" },
      { accountNumber: "1002", accountName: "EZ-Lazy Foods", accountAddress: "88 Market Rd, Winnipeg, MB", shippingInfo: "Back door / 8:00-10:00" },
      { accountNumber: "2001", accountName: "North Plant", accountAddress: "5 Industrial Ave, Brandon, MB", shippingInfo: "Gate B / Call ahead" },
      { accountNumber: "3007", accountName: "TDG Customer Demo", accountAddress: "77 Demo Blvd, Dauphin, MB", shippingInfo: "Main entrance" },
    ];
    setCustomers(customers);
    alert("已写入演示客户库");
  }

  function renderCustomers() {
    const q = safe($("custSearch").value).toLowerCase();
    const list = getCustomers()
      .filter((c) => {
        if (!q) return true;
        return (
          (c.accountNumber || "").toLowerCase().includes(q) ||
          (c.accountName || "").toLowerCase().includes(q) ||
          (c.accountAddress || "").toLowerCase().includes(q)
        );
      })
      .sort((a,b) => (a.accountNumber||"").localeCompare(b.accountNumber||""));

    const rows = list.map((c, idx) => `
      <tr>
        <td>
          <div style="font-weight:800">${escapeHtml(c.accountNumber)}</div>
          <div class="muted" style="margin-top:6px">${escapeHtml(c.accountName)}</div>
        </td>
        <td class="muted">${escapeHtml(c.accountAddress || "")}</td>
        <td class="muted">${escapeHtml(c.shippingInfo || "")}</td>
        <td style="white-space:nowrap">
          <button class="btn secondary" data-edit-cust="${idx}" type="button">编辑</button>
          <button class="btn warn" data-del-cust="${idx}" type="button">删除</button>
        </td>
      </tr>
    `).join("");

    $("customersTableWrap").innerHTML = `
      <table class="table">
        <thead>
          <tr><th>Account</th><th>Address</th><th>Shipping</th><th>操作</th></tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="4">无数据</td></tr>`}</tbody>
      </table>
    `;

    document.querySelectorAll("[data-edit-cust]").forEach((btn) => {
      btn.addEventListener("click", () => editCustomer(Number(btn.getAttribute("data-edit-cust"))), { passive: true });
    });
    document.querySelectorAll("[data-del-cust]").forEach((btn) => {
      btn.addEventListener("click", () => deleteCustomer(Number(btn.getAttribute("data-del-cust"))), { passive: true });
    });
  }

  function addCustomer() {
    const html = `
      <div class="row2">
        <div>
          <label>Account Number</label>
          <input id="c_no" placeholder="1008" />
        </div>
        <div>
          <label>Account Name</label>
          <input id="c_name" placeholder="Customer Name" />
        </div>
      </div>
      <div style="margin-top:10px">
        <label>Account Address</label>
        <input id="c_addr" placeholder="Street, City, Province" />
      </div>
      <div style="margin-top:10px">
        <label>Shipping Info</label>
        <input id="c_ship" placeholder="Dock / time window" />
      </div>
      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">取消</button>
        <button class="btn ok" id="btnCreate" type="button">创建</button>
      </div>
    `;

    const modal = openModal("新增客户", html, { onClose: renderAll });
    field("btnCancel").onclick = () => modal.close();
    field("btnCreate").onclick = () => {
      const no = safe(field("c_no").value);
      const name = safe(field("c_name").value);
      if (!no || !name) return alert("Account Number / Name 不能为空");

      const list = getCustomers();
      if (list.some((x) => safe(x.accountNumber) === no)) return alert("Account Number 已存在");

      list.push({
        accountNumber: no,
        accountName: name,
        accountAddress: safe(field("c_addr").value),
        shippingInfo: safe(field("c_ship").value),
      });
      setCustomers(list);
      modal.close();
      alert("已创建");
    };
  }

  function editCustomer(index) {
    const list = getCustomers();
    const c = list[index];
    if (!c) return;

    const html = `
      <div class="row2">
        <div>
          <label>Account Number</label>
          <input id="c_no" value="${escapeHtml(c.accountNumber)}" />
        </div>
        <div>
          <label>Account Name</label>
          <input id="c_name" value="${escapeHtml(c.accountName)}" />
        </div>
      </div>
      <div style="margin-top:10px">
        <label>Account Address</label>
        <input id="c_addr" value="${escapeHtml(c.accountAddress || "")}" />
      </div>
      <div style="margin-top:10px">
        <label>Shipping Info</label>
        <input id="c_ship" value="${escapeHtml(c.shippingInfo || "")}" />
      </div>
      <div class="divider"></div>
      <div class="right-actions">
        <button class="btn secondary" id="btnCancel" type="button">取消</button>
        <button class="btn ok" id="btnSave" type="button">保存</button>
      </div>
    `;

    const modal = openModal("编辑客户", html, { onClose: renderAll });
    field("btnCancel").onclick = () => modal.close();
    field("btnSave").onclick = () => {
      const no = safe(field("c_no").value);
      const name = safe(field("c_name").value);
      if (!no || !name) return alert("Account Number / Name 不能为空");

      if (list.some((x, i) => i !== index && safe(x.accountNumber) === no)) return alert("Account Number 已存在");

      c.accountNumber = no;
      c.accountName = name;
      c.accountAddress = safe(field("c_addr").value);
      c.shippingInfo = safe(field("c_ship").value);
      list[index] = c;
      setCustomers(list);
      modal.close();
      alert("已保存");
    };
  }

  function deleteCustomer(index) {
    const list = getCustomers();
    const c = list[index];
    if (!c) return;
    if (!confirm(`确定删除客户：${c.accountNumber} / ${c.accountName} ?`)) return;
    list.splice(index, 1);
    setCustomers(list);
    renderAll();
  }

  function dangerResetAll() {
    if (!confirm("⚠️确定清空所有本地数据？（不可恢复）")) return;
    localStorage.clear();
    sessionStorage.clear();
    alert("已清空。将返回登录页。");
    window.location.href = "./login.html";
  }

  $("userSearch").addEventListener("input", renderUsers, { passive: true });
  $("custSearch").addEventListener("input", renderCustomers, { passive: true });

  $("btnAddUser").addEventListener("click", addUser, { passive: true });
  $("btnExportUsers").addEventListener("click", async () => {
    await window.TDG_AUTH.ensureSeedAdmin();
    exportJson(window.TDG_AUTH.getUsers(), "tdg-users.json");
  }, { passive: true });

  $("importUsersFile").addEventListener("change", async (e) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    try {
      const data = await readJsonFile(f);
      if (!Array.isArray(data)) return alert("导入失败：JSON 需为数组");
      const ok = data.every((u) => u && u.id && u.username && u.passwordHash);
      if (!ok) return alert("导入失败：缺少必要字段（id/username/passwordHash）");
      window.TDG_AUTH.setUsers(data);
      alert("导入成功");
      renderAll();
    } catch {
      alert("导入失败：文件不是有效 JSON");
    }
  });

  $("btnAddCustomer").addEventListener("click", addCustomer, { passive: true });

// CSV import customers (upsert by accountNumber)
function parseCsv(text) {
  // Basic CSV parser with quotes support
  const rows = [];
  let row = [];
  let cur = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        cur += '"'; i++; continue;
      }
      if (ch === '"') { inQuotes = false; continue; }
      cur += ch; continue;
    }

    if (ch === '"') { inQuotes = true; continue; }
    if (ch === ",") { row.push(cur); cur = ""; continue; }
    if (ch === "\r") { continue; }
    if (ch === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; continue; }
    cur += ch;
  }
  // last cell
  if (cur.length || row.length) { row.push(cur); rows.push(row); }
  return rows;
}

function normHeader(s) {
  return String(s || "").trim().toLowerCase();
}

function pickIndex(headers, candidates) {
  const h = headers.map(normHeader);
  for (const cand of candidates) {
    const idx = h.indexOf(normHeader(cand));
    if (idx >= 0) return idx;
  }
  return -1;
}

async function readTextFile(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onerror = () => reject(new Error("读取文件失败"));
    fr.onload = () => resolve(String(fr.result || ""));
    fr.readAsText(file);
  });
}

$("importCustomersCsv")?.addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  e.target.value = "";
  if (!f) return;
  try {
    const text = await readTextFile(f);
    const rows = parseCsv(text).filter(r => r.some(c => String(c || "").trim() !== ""));
    if (!rows.length) return alert("CSV为空");

    const headers = rows[0] || [];
    const idxAcc = pickIndex(headers, ["position", "account number", "account no", "account", "accountnumber", "account_number"]);
    const idxName = pickIndex(headers, ["customer name", "customer", "account name", "name", "accountname", "account_name"]);
    const idxAddr = pickIndex(headers, ["address", "account address", "addr", "accountaddress", "account_address"]);

    if (idxAcc < 0 || idxName < 0) {
      return alert("CSV表头未识别：需要包含账号(position/account number)和客户名(customer name)");
    }

    const existing = getCustomers();
    const map = new Map(existing.map(c => [String(c.accountNumber), c]));
    let added = 0, updated = 0, skipped = 0;

    for (let i = 1; i < rows.length; i++) {
      const r = rows[i];
      const accountNumber = String(r[idxAcc] ?? "").trim();
      const accountName = String(r[idxName] ?? "").trim();
      const accountAddress = idxAddr >= 0 ? String(r[idxAddr] ?? "").trim() : "";

      if (!accountNumber || !accountName) { skipped++; continue; }

      if (map.has(accountNumber)) {
        const cur = map.get(accountNumber);
        cur.accountName = accountName || cur.accountName;
        if (accountAddress) cur.accountAddress = accountAddress;
        map.set(accountNumber, cur);
        updated++;
      } else {
        map.set(accountNumber, {
          id: `c_${Date.now()}_${Math.random().toString(16).slice(2)}`,
          accountNumber,
          accountName,
          accountAddress: accountAddress || "",
        });
        added++;
      }
    }

    const merged = Array.from(map.values());
    setCustomers(merged);
    alert(`导入完成：新增 ${added}，更新 ${updated}，跳过 ${skipped}`);
    renderAll();
  } catch (err) {
    alert("导入失败：" + String(err?.message || err));
  }
});

        $("btnDangerResetAll").addEventListener("click", dangerResetAll, { passive: true });

  function renderAll() {
    renderUsers();
    renderCustomers();
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  renderAll();
})();