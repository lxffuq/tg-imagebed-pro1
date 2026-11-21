const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra }
});
const err = (message, status = 400) => json({ error: message }, status);
const cleanName = (s) => (s || "image").replace(/[\\/:*?"<>|\x00-\x1f]/g, "_").slice(0, 180);
const isImage = (mime) => /^image\/(jpeg|png|gif|webp|avif|bmp|svg\+xml)$/i.test(mime || "");
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array((s.match(/../g) || []).map(h => parseInt(h, 16)));
const sha256hex = async (text) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
// 管理密码：PBKDF2-SHA256 10 万次迭代，盐 16 字节，存 D1 settings 表
async function hashPassword(password, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return hex(salt) + ":" + hex(bits);
}
let tablesReady = false;
async function ensureTables(env) {
  if (tablesReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, original_name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, telegram_chat_id TEXT NOT NULL, telegram_message_id INTEGER NOT NULL, telegram_file_id TEXT NOT NULL, telegram_file_unique_id TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), status TEXT NOT NULL DEFAULT 'active', delete_error TEXT)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_created ON images(created_at DESC)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_name ON images(original_name)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_status ON images(status)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)"),
  ]);
  tablesReady = true;
}
async function getPasswordHash(env) {
  try { const row = await env.DB.prepare("SELECT value FROM settings WHERE key='admin_password_hash'").first(); return row?.value || null; }
  catch { return null; }
}
async function checkPassword(env, password) {
  if (!password) return false;
  if (env.ADMIN_TOKEN && safeEqual(password, env.ADMIN_TOKEN)) return true;
  const stored = await getPasswordHash(env);
  if (!stored) return false;
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const computed = await hashPassword(password, salt);
  return safeEqual(computed.split(":")[1], hash);
}
async function newSession(env) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)").bind(await sha256hex(token), now, now + 7 * 86400).run();
  return token;
}
async function verifySession(env, token) {
  if (!token) return false;
  try {
    const row = await env.DB.prepare("SELECT expires_at FROM sessions WHERE token_hash=?").bind(await sha256hex(token)).first();
    return !!row && row.expires_at > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
// 鉴权：部署时设了 ADMIN_TOKEN 变量/密钥可直接当口令；否则认 D1 会话
async function auth(request, env) {
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!bearer) return false;
  if (env.ADMIN_TOKEN && safeEqual(bearer, env.ADMIN_TOKEN)) return true;
  return verifySession(env, bearer);
}
const telegram = (botToken, method) => `https://api.telegram.org/bot${botToken}/${method}`;
// 机器人配置：优先用部署变量/密钥，其次用设置页绑定后存在 D1 里的值
async function getTelegramConfig(env) {
  let botToken = env.TG_BOT_TOKEN || "";
  let chatId = env.TG_CHAT_ID || "";
  if (!botToken || !chatId) {
    try {
      const { results = [] } = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('tg_bot_token','tg_chat_id')").all();
      for (const r of results) {
        if (r.key === "tg_bot_token" && !botToken) botToken = r.value;
        if (r.key === "tg_chat_id" && !chatId) chatId = r.value;
      }
    } catch {}
  }
  return { botToken, chatId };
}

async function api(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === "/api/health") return json({ ok: true, service: "TG ImageBed Pro" });

  // 首次设置密码：部署成功后第一次打开站点时调用，之后不再开放
  if (url.pathname === "/api/auth/status") {
    await ensureTables(env);
    return json({ setupRequired: !env.ADMIN_TOKEN && !(await getPasswordHash(env)) });
  }
  if (url.pathname === "/api/auth/setup" && request.method === "POST") {
    await ensureTables(env);
    if (env.ADMIN_TOKEN || (await getPasswordHash(env))) return err("管理密码已设置", 409);
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || "");
    if (password.length < 6) return err("密码至少 6 位", 400);
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)").bind(await hashPassword(password)).run();
    return json({ token: await newSession(env) });
  }
  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    if (!(await checkPassword(env, String(body.password || "")))) return err("密码不正确", 401);
    return json({ token: await newSession(env) });
  }
  if (url.pathname === "/api/auth/change" && request.method === "POST") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    if (!(await checkPassword(env, String(body.oldPassword || "")))) return err("当前密码不正确", 401);
    const np = String(body.newPassword || "");
    if (np.length < 6) return err("新密码至少 6 位", 400);
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(await hashPassword(np)).run();
    await env.DB.prepare("DELETE FROM sessions").run();
    return json({ token: await newSession(env) });
  }
  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (bearer) { try { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256hex(bearer)).run(); } catch {} }
    return json({ ok: true });
  }

  // 绑定 Telegram 机器人：保存前先调 getMe 校验 Token，再调 getChatMember 确认机器人是该频道管理员
  if (url.pathname === "/api/settings/telegram" && request.method === "GET") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    const cfg = await getTelegramConfig(env);
    let username = null;
    try { const row = await env.DB.prepare("SELECT value FROM settings WHERE key='tg_bot_username'").first(); username = row?.value || null; } catch {}
    return json({ configured: !!(cfg.botToken && cfg.chatId), hasBotToken: !!cfg.botToken, chatId: cfg.chatId || null, botUsername: username, fromEnv: !!(env.TG_BOT_TOKEN && env.TG_CHAT_ID) });
  }
  if (url.pathname === "/api/settings/telegram" && request.method === "POST") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    const botToken = String(body.botToken || "").trim();
    const chatId = String(body.chatId || "").trim();
    if (!botToken && !chatId) {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM settings WHERE key='tg_bot_token'"),
        env.DB.prepare("DELETE FROM settings WHERE key='tg_chat_id'"),
        env.DB.prepare("DELETE FROM settings WHERE key='tg_bot_username'"),
      ]);
      return json({ configured: false });
    }
    // Token 留空时沿用已保存的 Token（已绑定后只换频道不用重填）
    let tokenToUse = botToken;
    if (!tokenToUse) { const cfg = await getTelegramConfig(env); tokenToUse = cfg.botToken || ""; }
    if (!tokenToUse) return err("请填写机器人 Token", 400);
    if (!/^\d+:[A-Za-z0-9_-]{35}$/.test(tokenToUse)) return err("机器人 Token 格式不对（应为 数字:35位字符）", 400);
    if (!/^-?\d+$/.test(chatId)) return err("频道 ID 格式不对（应为 -100 开头的数字）", 400);
    let me;
    try { me = await (await fetch(`https://api.telegram.org/bot${tokenToUse}/getMe`)).json(); }
    catch { return err("连接 Telegram 失败，请稍后重试", 502); }
    if (!me.ok) return err("机器人 Token 无效（Telegram 返回：" + (me.description || "Unauthorized") + "）", 400);
    let member;
    try {
      member = await (await fetch(`https://api.telegram.org/bot${tokenToUse}/getChatMember`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chatId, user_id: me.result.id }) })).json();
    } catch { return err("连接 Telegram 失败，请稍后重试", 502); }
    if (!member.ok) return err("频道 ID 无效或机器人不在该频道（" + (member.description || "") + "）", 400);
    if (member.result.status !== "administrator" && member.result.status !== "creator") return err("机器人不是该频道管理员，请先把机器人加为频道管理员", 400);
    const username = "@" + (me.result.username || "");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_bot_token', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(tokenToUse),
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_chat_id', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(chatId),
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_bot_username', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(username),
    ]);
    return json({ configured: true, chatId, botUsername: username });
  }

  if (!(await auth(request, env))) return err("Unauthorized", 401);

  if (url.pathname === "/api/stats" && request.method === "GET") {
    const total = await env.DB.prepare("SELECT COUNT(*) AS c FROM images WHERE status='active'").first();
    const bytes = await env.DB.prepare("SELECT COALESCE(SUM(size_bytes),0) AS s FROM images WHERE status='active'").first();
    const today = await env.DB.prepare("SELECT COUNT(*) AS c FROM images WHERE status='active' AND date(created_at,'+8 hours') = date('now','+8 hours')").first();
    const n = total?.c || 0;
    return json({ total: n, totalBytes: bytes?.s || 0, today: today?.c || 0, success: n });
  }

  if (url.pathname === "/api/images" && request.method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page") || 1));
    const limit = Math.min(60, Math.max(1, Number(url.searchParams.get("limit") || 24)));
    const q = (url.searchParams.get("q") || "").trim().slice(0, 120);
    const filter = url.searchParams.get("filter") || "";
    const where = filter === "today"
      ? "status = 'active' AND date(created_at,'+8 hours') = date('now','+8 hours')"
      : "status = 'active'";
    const count = q
      ? await env.DB.prepare(`SELECT COUNT(*) AS total FROM images WHERE ${where} AND original_name LIKE ?`).bind(`%${q}%`).first()
      : await env.DB.prepare(`SELECT COUNT(*) AS total FROM images WHERE ${where}`).first();
    const stmt = q
      ? env.DB.prepare(`SELECT id, original_name, mime_type, size_bytes, created_at FROM images WHERE ${where} AND original_name LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(`%${q}%`, limit, (page - 1) * limit)
      : env.DB.prepare(`SELECT id, original_name, mime_type, size_bytes, created_at FROM images WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(limit, (page - 1) * limit);
    const { results = [] } = await stmt.all();
    return json({ items: results, total: count?.total || 0, page, limit, pages: Math.max(1, Math.ceil((count?.total || 0) / limit)) });
  }

  if (url.pathname === "/api/upload" && request.method === "POST") {
    const cfg = await getTelegramConfig(env);
    if (!cfg.botToken || !cfg.chatId) return err("未绑定 Telegram 机器人，请先在设置里绑定", 400);
    const form = await request.formData();
    const files = form.getAll("files").filter(x => x instanceof File);
    if (!files.length) return err("请先选择图片");
    if (files.length > 20) return err("单次最多上传20张图片");
    const out = [];
    for (const file of files) {
      if (!isImage(file.type)) { out.push({ name: file.name, ok: false, error: "仅支持图片格式" }); continue; }
      if (file.size > 20 * 1024 * 1024) { out.push({ name: file.name, ok: false, error: "单张图片最大20MB" }); continue; }
      try {
        const fd = new FormData();
        fd.set("chat_id", cfg.chatId);
        fd.set("document", file, cleanName(file.name));
        const tgRes = await fetch(telegram(cfg.botToken, "sendDocument"), { method: "POST", body: fd });
        const tg = await tgRes.json();
        if (!tg.ok) throw new Error(tg.description || "Telegram上传失败");
        const doc = tg.result.document;
        const id = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO images (id, original_name, mime_type, size_bytes, telegram_chat_id, telegram_message_id, telegram_file_id, telegram_file_unique_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .bind(id, cleanName(file.name), file.type || "application/octet-stream", file.size, cfg.chatId, tg.result.message_id, doc.file_id, doc.file_unique_id || null).run();
        out.push({ name: file.name, ok: true, id, url: `${url.origin}/i/${id}` });
      } catch (e) { out.push({ name: file.name, ok: false, error: e.message || "上传失败" }); }
    }
    return json({ results: out });
  }

  if (url.pathname === "/api/delete" && request.method === "POST") {
    const cfg = await getTelegramConfig(env);
    const body = await request.json().catch(() => ({}));
    const ids = [...new Set((Array.isArray(body.ids) ? body.ids : []).filter(x => typeof x === "string"))].slice(0, 100);
    if (!ids.length) return err("没有选择图片");
    let deleted = 0, queued = 0;
    for (const id of ids) {
      const row = await env.DB.prepare("SELECT * FROM images WHERE id = ? AND status = 'active'").bind(id).first();
      if (!row) continue;
      // Hide it from the UI immediately, even if Telegram deletion needs retry.
      await env.DB.prepare("UPDATE images SET status='deleting' WHERE id=?").bind(id).run();
      const cacheKey = new Request(`${url.origin}/i/${id}`);
      ctx.waitUntil(caches.default.delete(cacheKey));
      try {
        if (!cfg.botToken) throw new Error("未绑定 Telegram 机器人，请先在设置里绑定");
        const r = await fetch(telegram(cfg.botToken, "deleteMessage"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: row.telegram_chat_id, message_id: row.telegram_message_id }) });
        const j = await r.json();
        if (!j.ok && !/message to delete not found/i.test(j.description || "")) throw new Error(j.description || "Telegram删除失败");
        await env.DB.prepare("DELETE FROM images WHERE id=?").bind(id).run(); deleted++;
      } catch (e) {
        await env.DB.prepare("UPDATE images SET delete_error=? WHERE id=?").bind(String(e.message).slice(0, 500), id).run(); queued++;
      }
    }
    return json({ deleted, queued, hidden: ids.length });
  }
  return err("Not found", 404);
}

async function serveImage(request, env, ctx) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  const cache = caches.default;
  // v2 缓存键：旧缓存里存的是 attachment（强制下载），换键后不再命中旧缓存
  const cacheKey = new Request(`${url.origin}/i/${id}?v=2`);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;
  const row = await env.DB.prepare("SELECT * FROM images WHERE id=? AND status='active'").bind(id).first();
  if (!row) return new Response("Not found", { status: 404 });
  const cfg = await getTelegramConfig(env);
  if (!cfg.botToken) return new Response("未绑定 Telegram 机器人，请先在设置里绑定", { status: 503 });
  const gf = await fetch(telegram(cfg.botToken, "getFile"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ file_id: row.telegram_file_id }) });
  const gj = await gf.json();
  if (!gj.ok || !gj.result?.file_path) return new Response("Telegram file unavailable", { status: 502 });
  const fileUrl = `https://api.telegram.org/file/bot${cfg.botToken}/${gj.result.file_path}`;
  const upstream = await fetch(fileUrl);
  if (!upstream.ok) return new Response("Image fetch failed", { status: 502 });
  const headers = new Headers(upstream.headers);
  const ext = (row.original_name || "").split(".").pop().toLowerCase();
  const extCt = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif", avif: "image/avif", bmp: "image/bmp", svg: "image/svg+xml" }[ext];
  headers.set("content-type", (row.mime_type && row.mime_type.startsWith("image/")) ? row.mime_type : (extCt || headers.get("content-type") || "application/octet-stream"));
  // 浏览器内直接预览而不是下载：Telegram 上游返回的是 attachment，这里改成 inline
  headers.set("content-disposition", "inline; filename*=UTF-8''" + encodeURIComponent(row.original_name || "image"));
  headers.set("cache-control", "public, max-age=86400, s-maxage=604800");
  headers.set("access-control-allow-origin", "*");
  headers.set("x-content-type-options", "nosniff");
  const response = new Response(upstream.body, { status: 200, headers });
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

async function retryDeletes(env) {
  const cfg = await getTelegramConfig(env);
  if (!cfg.botToken) return;
  const { results = [] } = await env.DB.prepare("SELECT id, telegram_chat_id, telegram_message_id FROM images WHERE status='deleting' LIMIT 50").all();
  for (const row of results) {
    try {
      const r = await fetch(telegram(cfg.botToken, "deleteMessage"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: row.telegram_chat_id, message_id: row.telegram_message_id }) });
      const j = await r.json();
      if (j.ok || /message to delete not found/i.test(j.description || "")) await env.DB.prepare("DELETE FROM images WHERE id=?").bind(row.id).run();
      else await env.DB.prepare("UPDATE images SET delete_error=? WHERE id=?").bind(j.description || "Telegram删除失败", row.id).run();
    } catch (e) { await env.DB.prepare("UPDATE images SET delete_error=? WHERE id=?").bind(String(e.message).slice(0, 500), row.id).run(); }
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try { await ensureTables(env); } catch {}
    if (url.pathname.startsWith("/api/")) return api(request, env, ctx);
    if (url.pathname.startsWith("/i/")) return serveImage(request, env, ctx);
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) { await ensureTables(env); ctx.waitUntil(retryDeletes(env)); }
};
