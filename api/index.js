// ============================================
// REBELS ANTI-DOWNLOADER — VERCEL BACKEND
// KV: Upstash Redis via @upstash/redis
//
// ENV VARS (set di Vercel Dashboard → Settings → Env):
//   UPSTASH_REDIS_REST_URL   — dari Upstash console
//   UPSTASH_REDIS_REST_TOKEN — dari Upstash console
//   ADMIN_KEY                — password admin kamu
//
// SCRIPT KEY di Redis: "recorder" (value = base64 encoded script)
// ============================================

import { Redis } from '@upstash/redis';

// ── Upstash Redis client ──────────────────────────────────────────────────────
const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// ── In-memory stores (per instance, resets on cold start) ────────────────────
const requestCounts = new Map();
const suspiciousIPs = new Set();
const tokenUsage    = new Map();

// ── Config ───────────────────────────────────────────────────────────────────
const CONFIG = {
  MAX_REQUESTS_PER_MINUTE : 10,
  MAX_REQUESTS_PER_HOUR   : 50,
  MAX_TOKEN_USES          : 1,
  BLOCK_DURATION          : 3_600_000,
  TOKEN_LIFETIME          : 10_000,   // 10s — lebih longgar untuk Vercel cold start
  KV_SCRIPT_KEY           : 'recorder',
  get ADMIN_KEY() { return process.env.ADMIN_KEY || 'Rebelsh4x0r'; },
};

// ── CORS headers ─────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin' : '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// ═════════════════════════════════════════════════════════════════════════════
// REDIS HELPERS
// ═════════════════════════════════════════════════════════════════════════════

async function rGet(key) {
  try { return await redis.get(key); }
  catch (e) { console.error('[redis.get]', e.message); return null; }
}

async function rSet(key, value, ttl = null) {
  try {
    if (ttl) await redis.set(key, value, { ex: ttl });
    else     await redis.set(key, value);
    return true;
  } catch (e) { console.error('[redis.set]', e.message); return false; }
}

async function rDel(key) {
  try { await redis.del(key); return true; }
  catch (e) { console.error('[redis.del]', e.message); return false; }
}

/** List all keys matching prefix using SCAN */
async function rKeys(prefix) {
  try {
    const keys = [];
    let cursor = 0;
    do {
      const [nextCursor, batch] = await redis.scan(cursor, { match: `${prefix}*`, count: 100 });
      keys.push(...batch);
      cursor = Number(nextCursor);
    } while (cursor !== 0);
    return keys;
  } catch (e) { console.error('[redis.keys]', e.message); return []; }
}

// ═════════════════════════════════════════════════════════════════════════════
// HWID FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

async function checkUserHWID(username, hwid) {
  try {
    const stored = await rGet(`user:${username}`);
    if (!stored) {
      await rSet(`user:${username}`, hwid, 31_536_000); // 1 year
      return { valid: true, isNewUser: true };
    }
    if (stored !== hwid) {
      return { valid: false, reason: `Username ${username} sudah terdaftar di device lain!`, storedHWID: stored };
    }
    return { valid: true, isNewUser: false };
  } catch (e) {
    return { valid: false, reason: 'Database error: ' + e.message };
  }
}

async function resetUserHWID(username) {
  const ok = await rDel(`user:${username}`);
  return ok ? { success: true } : { success: false, error: 'Redis delete failed' };
}

async function getUserHWIDInfo(username) {
  try {
    const hwid = await rGet(`user:${username}`);
    return { username, hwid: hwid || 'Not registered', exists: !!hwid };
  } catch (e) {
    return { error: e.message };
  }
}

async function getAllUsers() {
  try {
    const keys = await rKeys('user:');
    const users = await Promise.all(
      keys.map(async (key) => {
        const username = key.replace('user:', '');
        const hwid     = await rGet(key);
        return { username, hwid: hwid || 'unknown', registered: true };
      })
    );
    return users;
  } catch (e) {
    console.error('[getAllUsers]', e.message);
    return [];
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY
// ═════════════════════════════════════════════════════════════════════════════

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['cf-connecting-ip'] ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

function isSuspicious(req, ip) {
  const h          = req.headers;
  const ua         = h['user-agent'] || '';
  const isRobloxUA = /roblox/i.test(ua);

  // Blokir bot/scraper
  if (/curl|wget|python|bot|spider|crawler/i.test(ua))
    return { suspicious: true, reason: 'Mau Ngapain bang?' };

  // Roblox UA tapi ada browser fingerprint = executor yang coba scrape
  if (isRobloxUA) {
    const browserSigns = [
      h['sec-ch-ua'], h['sec-ch-ua-platform'],
      h['sec-fetch-site'], h['sec-fetch-mode'], h['sec-fetch-dest'],
      h['referer'], h['cookie'],
    ].filter(Boolean).length;
    if (browserSigns >= 2) return { suspicious: true, reason: 'Mau Ngapain Bang?' };
    if (h['accept']?.includes('text/html')) return { suspicious: true, reason: 'Mau Ngapain bang?' };
  }

  // Rate limiting
  const now = Date.now();
  if (!requestCounts.has(ip)) requestCounts.set(ip, { m: [], h: [] });
  const c = requestCounts.get(ip);
  c.m = c.m.filter(t => now - t < 60_000);
  c.h = c.h.filter(t => now - t < 3_600_000);
  c.m.push(now);
  c.h.push(now);
  if (c.m.length > CONFIG.MAX_REQUESTS_PER_MINUTE) return { suspicious: true, reason: 'Too many requests per minute' };
  if (c.h.length > CONFIG.MAX_REQUESTS_PER_HOUR)   return { suspicious: true, reason: 'Too many requests per hour' };
  if (c.m.length >= 3) {
    const r = c.m.slice(-3);
    if ((r[2] - r[0]) / 2 < 500) return { suspicious: true, reason: 'Request flooding detected' };
  }
  return { suspicious: false };
}

function generateClientID(req) {
  const ua    = req.headers['user-agent'] || 'unknown';
  const ip    = getIP(req);
  const rayId = req.headers['cf-ray'] || req.headers['x-vercel-id'] || 'unknown';
  return Buffer.from(`${ip}_${ua}_${rayId}`).toString('base64').replace(/=/g, '').slice(0, 16);
}

function generateToken(req) {
  const ts          = Date.now();
  const ip          = getIP(req);
  const ua          = req.headers['user-agent'] || 'unknown';
  const clientID    = generateClientID(req);
  const fingerprint = Buffer.from(`${ip}_${ua.slice(0, 20)}_${ts}`).toString('base64').replace(/=/g, '').slice(0, 24);
  const rand        = Array.from({ length: 32 }, () =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 62)]
  ).join('');
  return Buffer.from(`${ts}_${clientID}_${fingerprint}_pending_${rand}`).toString('base64');
}

function validateToken(token, req, hwid) {
  try {
    if (!token) return { valid: false, reason: 'Token kosong' };
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts   = decoded.split('_');
    if (parts.length < 5) return { valid: false, reason: 'Format token invalid' };

    const [tsStr, clientID, fingerprint] = parts;
    const ts = parseInt(tsStr);
    if (isNaN(ts)) return { valid: false, reason: 'Token corrupt' };
    if (Date.now() - ts > CONFIG.TOKEN_LIFETIME) return { valid: false, reason: 'Token expired' };

    // Usage tracking
    if (!tokenUsage.has(token)) tokenUsage.set(token, { count: 0, firstUse: Date.now() });
    const usage = tokenUsage.get(token);
    usage.count++;
    if (usage.count > CONFIG.MAX_TOKEN_USES) return { valid: false, reason: 'Token sudah digunakan' };

    // Client validation
    if (generateClientID(req) !== clientID) return { valid: false, reason: 'Client tidak cocok' };

    const ip          = getIP(req);
    const ua          = req.headers['user-agent'] || '';
    const expectedFP  = Buffer.from(`${ip}_${ua.slice(0, 20)}_${ts}`).toString('base64').replace(/=/g, '').slice(0, 24);
    if (fingerprint !== expectedFP) return { valid: false, reason: 'Fingerprint tidak cocok' };

    return { valid: true, usage: usage.count };
  } catch (e) {
    return { valid: false, reason: 'Token error: ' + e.message };
  }
}

function cleanupMemory() {
  const now = Date.now();
  for (const [ip, c] of requestCounts) {
    c.m = c.m.filter(t => now - t < 60_000);
    c.h = c.h.filter(t => now - t < 3_600_000);
    if (!c.m.length && !c.h.length) requestCounts.delete(ip);
  }
  for (const [tok, u] of tokenUsage) {
    if (now - u.firstUse > CONFIG.TOKEN_LIFETIME * 3) tokenUsage.delete(tok);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// LUA OBFUSCATION ENGINE
// ═════════════════════════════════════════════════════════════════════════════

class Obf {
  varName() {
    const c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let n = c[Math.floor(Math.random() * 52)];
    for (let i = 0; i < 3; i++) n += c[Math.floor(Math.random() * 52)] + Math.floor(Math.random() * 10);
    return n;
  }

  encodeStr(str) {
    const bytes  = [...str].map(c => c.charCodeAt(0));
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 20) chunks.push(bytes.slice(i, i + 20));
    const cvars = chunks.map(() => this.varName());
    const hv    = this.varName(), rv = this.varName();
    let code = cvars.map((cv, i) => `local ${cv}={${chunks[i].join(',')}};`).join('\n') + '\n';
    code += `local ${hv}=function(t)local r=""for i=1,#t do r=r..string.char(t[i])end return r end;\n`;
    code += `local ${rv}=${hv}(${cvars[0]})` + cvars.slice(1).map(cv => `..${hv}(${cv})`).join('') + ';\n';
    return { code, varName: rv };
  }

  junk() {
    return Array.from({ length: 3 + Math.floor(Math.random() * 3) }, () => {
      const v   = this.varName();
      const val = Math.random() > 0.5 ? Math.floor(Math.random() * 9999) : `"${this.varName()}"`;
      return `local ${v}=${val};`;
    }).join('\n');
  }

  wrap(code) {
    const fv = this.varName(), sv = this.varName();
    return `local ${sv}={};\n${this.junk()}\nlocal function ${fv}()\n${code}\nend;\n${fv}();\n`;
  }
}

function buildNotif(obf) {
  const [ts, pl, gui, fr, img, tl, sl, stl, bar, fill, log] = Array.from({ length: 11 }, () => obf.varName());
  return `
local ${ts}=game:GetService("TweenService")
local ${pl}=game:GetService("Players").LocalPlayer
local RunService=game:GetService("RunService")
local function createNotif(callback)
  local ${gui}=Instance.new("ScreenGui")
  ${gui}.Name="LoadingScreen" ${gui}.ResetOnSpawn=false
  ${gui}.ZIndexBehavior=Enum.ZIndexBehavior.Sibling
  ${gui}.Parent=${pl}:WaitForChild("PlayerGui")
  local ${fr}=Instance.new("Frame")
  ${fr}.AnchorPoint=Vector2.new(0.5,0.5) ${fr}.Position=UDim2.new(0.5,0,0.5,0)
  ${fr}.Size=UDim2.new(0,0,0,0) ${fr}.BackgroundColor3=Color3.fromRGB(15,20,35)
  ${fr}.BackgroundTransparency=0.15 ${fr}.BorderSizePixel=0 ${fr}.Parent=${gui}
  local c=Instance.new("UICorner") c.CornerRadius=UDim.new(0,12) c.Parent=${fr}
  local sk=Instance.new("UIStroke") sk.Color=Color3.fromRGB(0,145,255)
  sk.Thickness=1.6 sk.Transparency=0.4 sk.Parent=${fr}
  local ${img}=Instance.new("ImageLabel")
  ${img}.Size=UDim2.new(0,80,0,80) ${img}.Position=UDim2.new(0.5,0,0,20)
  ${img}.AnchorPoint=Vector2.new(0.5,0) ${img}.BackgroundColor3=Color3.fromRGB(30,40,60)
  ${img}.BorderSizePixel=0
  ${img}.Image="https://www.roblox.com/headshot-thumbnail/image?userId="..${pl}.UserId.."&width=150&height=150&format=png"
  ${img}.Parent=${fr}
  local ac=Instance.new("UICorner") ac.CornerRadius=UDim.new(1,0) ac.Parent=${img}
  local as=Instance.new("UIStroke") as.Color=Color3.fromRGB(0,145,255) as.Thickness=2 as.Transparency=0.3 as.Parent=${img}
  local ${tl}=Instance.new("TextLabel")
  ${tl}.Size=UDim2.new(1,0,0,60) ${tl}.Position=UDim2.new(0,0,0,110)
  ${tl}.BackgroundTransparency=1 ${tl}.Font=Enum.Font.GothamBold ${tl}.Text="Auto Walk"
  ${tl}.TextColor3=Color3.fromRGB(255,255,255) ${tl}.TextScaled=true ${tl}.TextTransparency=1 ${tl}.Parent=${fr}
  local ${sl}=Instance.new("TextLabel")
  ${sl}.Size=UDim2.new(1,0,0,30) ${sl}.Position=UDim2.new(0,0,0,165)
  ${sl}.BackgroundTransparency=1 ${sl}.Font=Enum.Font.Gotham ${sl}.Text="Menunggu script load dulu"
  ${sl}.TextColor3=Color3.fromRGB(160,180,200) ${sl}.TextSize=18 ${sl}.TextTransparency=1 ${sl}.Parent=${fr}
  local ${stl}=Instance.new("TextLabel")
  ${stl}.Size=UDim2.new(1,0,0,24) ${stl}.Position=UDim2.new(0,0,0,200)
  ${stl}.BackgroundTransparency=1 ${stl}.Font=Enum.Font.Gotham ${stl}.Text="Status: Loading script."
  ${stl}.TextColor3=Color3.fromRGB(150,170,190) ${stl}.TextSize=14 ${stl}.TextTransparency=1 ${stl}.Parent=${fr}
  local bg=Instance.new("Frame") bg.AnchorPoint=Vector2.new(0.5,0)
  bg.Position=UDim2.new(0.5,0,0,230) bg.Size=UDim2.new(0.85,0,0,20)
  bg.BackgroundColor3=Color3.fromRGB(30,40,60) bg.BorderSizePixel=0 bg.Parent=${fr}
  local bc=Instance.new("UICorner") bc.CornerRadius=UDim.new(0,10) bc.Parent=bg
  local ${fill}=Instance.new("Frame")
  ${fill}.AnchorPoint=Vector2.new(0,0.5) ${fill}.Position=UDim2.new(0,0,0.5,0)
  ${fill}.Size=UDim2.new(0,0,1,0) ${fill}.BackgroundColor3=Color3.fromRGB(0,145,255)
  ${fill}.BorderSizePixel=0 ${fill}.Parent=bg
  local fc=Instance.new("UICorner") fc.CornerRadius=UDim.new(0,10) fc.Parent=${fill}
  local ${log}=Instance.new("TextLabel")
  ${log}.Size=UDim2.new(1,0,0,50) ${log}.Position=UDim2.new(0,0,0,260)
  ${log}.BackgroundTransparency=1 ${log}.Font=Enum.Font.Gotham
  ${log}.TextColor3=Color3.fromRGB(180,190,200) ${log}.TextSize=14
  ${log}.Text="- Booting main modules\\n- Getting Data\\n- Getting stuff ready"
  ${log}.TextTransparency=1 ${log}.Parent=${fr}
  ${ts}:Create(${fr},TweenInfo.new(0.4,Enum.EasingStyle.Back,Enum.EasingDirection.Out),{Size=UDim2.new(0,420,0,330)}):Play()
  task.wait(0.2)
  ${ts}:Create(${tl},TweenInfo.new(0.3),{TextTransparency=0}):Play()
  ${ts}:Create(${sl},TweenInfo.new(0.3),{TextTransparency=0}):Play()
  ${ts}:Create(${stl},TweenInfo.new(0.3),{TextTransparency=0}):Play()
  ${ts}:Create(${log},TweenInfo.new(0.3),{TextTransparency=0}):Play()
  local DUR=15
  local tw=${ts}:Create(${fill},TweenInfo.new(DUR,Enum.EasingStyle.Linear),{Size=UDim2.new(1,0,1,0)})
  tw:Play()
  local st=tick()
  local conn=RunService.Heartbeat:Connect(function()
    local e=tick()-st
    local p=math.clamp(e/DUR,0,1)
    ${stl}.Text=string.format("Status: Loading... %d%%",math.floor(p*100))
  end)
  task.delay(DUR+0.5,function()
    conn:Disconnect()
    for _,lbl in ipairs({${tl},${sl},${stl},${log}}) do
      ${ts}:Create(lbl,TweenInfo.new(0.3),{TextTransparency=1}):Play()
    end
    task.wait(0.2)
    ${ts}:Create(${fr},TweenInfo.new(0.4,Enum.EasingStyle.Back,Enum.EasingDirection.In),{Size=UDim2.new(0,0,0,0)}):Play()
    task.wait(0.5)
    ${gui}:Destroy()
    if callback and type(callback)=="function" then callback() end
  end)
end`;
}

function buildLoader(token, baseUrl) {
  const obf      = new Obf();
  const tokEnc   = obf.encodeStr(token);
  const [proto, domain] = baseUrl.split('://');
  const protoEnc = obf.encodeStr(proto);
  const domEnc   = obf.encodeStr(domain);
  const [hv, uv, rv, cv, usv] = Array.from({ length: 5 }, () => obf.varName());
  const notif = buildNotif(obf);

  const body = `
${obf.junk()}
if _G.GG_Rebels_main_loaded then return _G.GG end
${obf.junk()}
${notif}
${obf.junk()}
local ${hv}=(function()
  if gethwid then return gethwid()
  else return game:GetService("RbxAnalyticsService"):GetClientId() end
end)()
local ${usv}=game:GetService("Players").LocalPlayer.Name
${tokEnc.code}
${protoEnc.code}
${domEnc.code}
${obf.junk()}
local ${uv}=${protoEnc.varName}.."://"..${domEnc.varName}
  .."/?token="..${tokEnc.varName}
  .."&hwid="..${hv}
  .."&username="..${usv}
${obf.junk()}
local ok,${rv}=pcall(function()
  local hs=game:GetService("HttpService")
  local et=hs:UrlEncode(${tokEnc.varName})
  local eu=hs:UrlEncode(${usv})
  local url=${uv}:gsub("token="..${tokEnc.varName},"token="..et)
             :gsub("username="..${usv},"username="..eu)
  return game:HttpGet(url,true)
end)
if not ok then warn("Connection failed: "..tostring(${rv})) return end
if not ${rv} or ${rv}=="" then warn("Empty response") return end
${obf.junk()}
getgenv()._REBELS_VERIFIED=true
if not getgenv()._TELEPORT_SET then
  getgenv()._TELEPORT_SET=true
  pcall(function()
    local q='repeat task.wait()until game:IsLoaded()task.wait(2)pcall(function()loadstring(game:HttpGet("'..${protoEnc.varName}..'://'..${domEnc.varName}..'",true))()end)'
    if syn and syn.queue_on_teleport then syn.queue_on_teleport(q)
    elseif queue_on_teleport then queue_on_teleport(q) end
  end)
end
${obf.junk()}
createNotif(function()
  local ${cv},err=pcall(function()
    local fn,e=loadstring(${rv})
    if not fn then error("Parse error: "..tostring(e)) end
    _G.GG_Rebels_main_loaded=true
    local res=fn()
    if not _G.GG then error("Loadstring Only") end
    return res
  end)
  if not ${cv} then
    warn("Exec error: "..tostring(err))
    getgenv()._REBELS_VERIFIED=nil
    _G.GG_Rebels_main_loaded=nil
  end
end)
`;
  return obf.wrap(body);
}

// ═════════════════════════════════════════════════════════════════════════════
// RESPONSE HELPERS
// ═════════════════════════════════════════════════════════════════════════════

function json(res, data, status = 200) {
  res.status(status)
    .setHeader('Content-Type', 'application/json')
    .setHeader('Access-Control-Allow-Origin', '*')
    .end(JSON.stringify(data));
}

function text(res, body, status = 200, extra = {}) {
  Object.entries({ 'Content-Type': 'text/plain; charset=utf-8', ...CORS, ...extra })
    .forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).end(body);
}

function blocked(res, reason) {
  res.status(403)
    .setHeader('Content-Type', 'text/plain; charset=utf-8')
    .setHeader('X-Block-Reason', reason)
    .setHeader('X-Protected-By', 'Rebels')
    .end(`403 BLOCKED: ${reason}`);
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ═════════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  try {
    if (req.method === 'OPTIONS') {
      res.status(204);
      Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));
      res.end();
      return;
    }

    if (Math.random() < 0.02) cleanupMemory();

    const ip      = getIP(req);
    const ua      = req.headers['user-agent'] || '';
    const isRoblox = /roblox/i.test(ua);

    // Build origin for token generation
    const host   = req.headers['x-forwarded-host'] || req.headers['host'] || 'localhost:3000';
    const proto  = req.headers['x-forwarded-proto'] || 'https';
    const origin = `${proto}://${host}`;
    const url    = new URL(`${origin}${req.url}`);
    const path   = url.pathname;
    const q      = url.searchParams;

    // Block suspicious IPs
    if (suspiciousIPs.has(ip)) return blocked(res, 'IP kamu diblokir');

    // Suspicion check
    const sus = isSuspicious(req, ip);
    if (sus.suspicious) {
      suspiciousIPs.add(ip);
      setTimeout(() => suspiciousIPs.delete(ip), CONFIG.BLOCK_DURATION);
      return blocked(res, sus.reason);
    }

    // ────────────────────────────────────────────────────────────────────────
    // ADMIN API — key required
    // ────────────────────────────────────────────────────────────────────────

    if (path.startsWith('/admin/')) {
      if (q.get('key') !== CONFIG.ADMIN_KEY)
        return json(res, { success: false, error: 'Unauthorized' }, 401);

      // GET /admin/list-users
      if (path === '/admin/list-users') {
        const users = await getAllUsers();
        return json(res, { success: true, count: users.length, users });
      }

      // GET /admin/reset-hwid?username=xxx
      if (path === '/admin/reset-hwid') {
        const username = q.get('username');
        if (!username) return json(res, { success: false, error: 'username required' }, 400);
        const r = await resetUserHWID(username);
        return json(res, { success: r.success, username, message: r.success ? 'HWID reset' : r.error });
      }

      // GET /admin/check-hwid?username=xxx
      if (path === '/admin/check-hwid') {
        const username = q.get('username');
        if (!username) return json(res, { success: false, error: 'username required' }, 400);
        const info = await getUserHWIDInfo(username);
        return json(res, info);
      }

      return json(res, { error: 'Unknown admin route' }, 404);
    }

    // ────────────────────────────────────────────────────────────────────────
    // PUBLIC — Roblox only
    // ────────────────────────────────────────────────────────────────────────

    // GET /generate — generate fresh token
    if (path === '/generate') {
      if (!isRoblox) return blocked(res, 'Roblox only');
      return json(res, {
        success    : true,
        token      : generateToken(req),
        expires_in : `${CONFIG.TOKEN_LIFETIME / 1000}s`,
        max_uses   : CONFIG.MAX_TOKEN_USES,
      });
    }

    // GET / — no token → serve obfuscated loader
    if (path === '/' && !q.has('token')) {
      if (!isRoblox) return blocked(res, 'Roblox only — buka admin.html untuk panel admin');
      return text(res, buildLoader(generateToken(req), origin), 200, {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options': 'nosniff',
      });
    }

    // GET /?token=...&hwid=...&username=... — validate & serve script
    if (path === '/' && q.has('token')) {
      const token    = q.get('token');
      const hwid     = q.get('hwid')     || 'unknown';
      const username = q.get('username') || 'unknown';

      if (!isRoblox) return blocked(res, 'Roblox only');

      const validation = validateToken(token, req, hwid);
      if (!validation.valid) {
        suspiciousIPs.add(ip);
        return text(res, `-- Token invalid: ${validation.reason}\nerror("${validation.reason}")`, 403);
      }

      if (username === 'unknown' || hwid === 'unknown')
        return text(res, `-- Username/HWID tidak terdeteksi!\nerror("Auth failed")`, 403);

      const hwidCheck = await checkUserHWID(username, hwid);
      if (!hwidCheck.valid) {
        return text(
          res,
          `-- HWID ERROR: ${hwidCheck.reason}\n-- User: ${username}\n-- HWID: ${hwid}\nerror("${hwidCheck.reason}")`,
          403,
          { 'X-Block-Reason': 'HWID Mismatch' }
        );
      }

      const raw64 = await rGet(CONFIG.KV_SCRIPT_KEY);
      if (!raw64) return text(res, '-- Script belum tersedia di database', 500);

      let script;
      try {
        script = Buffer.from(String(raw64).replace(/\s+/g, ''), 'base64').toString('utf8');
      } catch {
        return text(res, '-- Script decode error', 500);
      }

      return text(res, script, 200, {
        'X-Token-Uses'   : String(validation.usage),
        'X-Protected'    : 'true',
        'X-HWID-Verified': 'true',
        'X-Username'     : username,
        'X-New-User'     : String(hwidCheck.isNewUser),
      });
    }

    return text(res, 'Not Found', 404);

  } catch (err) {
    console.error('[handler]', err);
    return text(res, 'Internal Server Error', 500);
  }
}
