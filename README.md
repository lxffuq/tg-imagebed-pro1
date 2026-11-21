# TG ImageBed Pro (MVP)

A mobile-first Telegram-backed image library with Cloudflare Worker + D1 index.

## MVP features
- Upload up to 20 images per batch (20 MB/image limit; Telegram Bot API compatibility)
- Telegram stores the uploaded image as a document (preserves original file)
- D1-backed paginated library and filename search
- Immediate hide from gallery when deleting; Telegram delete failures are retried by scheduled task
- Image proxy endpoint `/i/:id`, Cloudflare cache headers
- Mobile responsive UI; copy direct image URL; select/bulk delete

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/lxffuq/tg-imagebed-pro)

### 一键部署
点上面的按钮，登录 Cloudflare 账号后按提示部署：Worker 和 D1 数据库会自动建好，表结构在首次请求时自动创建，不用手动建库、不用跑 `schema.sql`。
部署完打开分配的域名：
1. 首次打开先设置管理密码。
2. 去设置 → Telegram 绑定机器人 Token 和频道 ID。

### 手动部署
1. Create a Telegram bot with BotFather. Keep the token private.
2. Create a private Telegram channel for storage; add the bot as administrator with permission to post/delete messages. Obtain the channel ID (usually `-100...`).
3. Deploy with Wrangler (or connect the GitHub repo in Cloudflare Workers & Pages and deploy). D1 数据库会按名字自动创建，表结构首次请求时自动创建；`schema.sql` 只是表结构的存档，一般不用手动跑。
4. Open the site once and set the admin password on the first-run screen (stored as a PBKDF2 hash in D1; sessions last 7 days). No dashboard step needed.
   Optional override: setting the `ADMIN_TOKEN` variable/secret also works as the admin password, and skips the first-run screen.
5. In Settings → Telegram, bind the bot: create a bot with BotFather, create a private channel, add the bot as administrator, and paste the bot token + channel ID (`-100...`). The site verifies the token and the bot's admin status before saving.
   Alternative: set `TG_BOT_TOKEN` / `TG_CHAT_ID` as Worker secrets instead; when set, they take precedence and the settings form is disabled.

CLI commands:
```bash
npm install -g wrangler
wrangler login
wrangler deploy
# open the site once, set the admin password, then bind the bot in Settings → Telegram
```

For static assets, Wrangler will upload `public/` under the Assets binding.

## Important limitations / notes
- Telegram is the storage backend; it is not an independent backup. Keep a second copy of irreplaceable images.
- Bot API limits and Telegram availability can change. MVP restricts image uploads to 20 MB to stay within conservative limits.
- D1 stores metadata and Telegram identifiers, not image bytes.
- Cache invalidation on delete is best-effort; the gallery record disappears immediately. Previously cached content may remain briefly at edge locations or in a browser cache.
- The project uses an admin bearer secret. Do not share it or commit secrets to GitHub.
- Before production use, consider adding rate limits, audit logs, token rotation, upload concurrency control, and an optional custom-domain cache purge integration.
