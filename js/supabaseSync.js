// /js/supabaseSync.js
(() => {
  "use strict";

  // 你 admin.js 里正在用的本地 key
  const StorageKeys = {
    customers: "tdg_customers_demo_v2",
  };

  const safe = (v) => String(v ?? "").trim();

  async function downloadCustomersToLocal() {
    // 这里的 supabase client 变量名取决于你的 supabaseClient.js
    // 常见做法：window.supabaseClient 或 window.supabase
    const sb = window.supabaseClient || window.supabase;
    if (!sb) throw new Error("Supabase client 未初始化（检查 supabaseClient.js）");

    // 假设你的表叫 customers，字段对齐你 admin.js 的结构：
    // accountNumber/accountName/accountAddress/city/route
    const { data, error } = await sb
      .from("customers")
      .select("accountNumber,accountName,accountAddress,city,route");

    if (error) throw error;

    const list = (data || []).map((c) => ({
      accountNumber: safe(c.accountNumber),
      accountName: safe(c.accountName),
      accountAddress: safe(c.accountAddress),
      city: safe(c.city),
      route: safe(c.route),
    }));

    localStorage.setItem(StorageKeys.customers, JSON.stringify(list));
    return list.length;
  }

  // 你可以扩展：downloadUsersToLocal() 等等

  window.TDG_SYNC = {
    downloadCustomersToLocal,
  };
})();