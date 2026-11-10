const VISITOR_COOKIE = "ca_vid";
const CONSENT_COOKIE = "ca_consent";
const ADMIN_COOKIE = "ca_admin";
const SESSION_COOKIE = "ca_session";
const VISITOR_MAX_AGE = 60 * 60 * 24 * 365;
const CONSENT_MAX_AGE = 60 * 60 * 24 * 180;
const ADMIN_MAX_AGE = 60 * 60 * 8;

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  try {
    if (path === "/api/health") {
      if (!env.DB) return json({ ok: false, service: "Control de accesos", database: false, error: "Falta la vinculación D1 DB." }, 503);
      await env.DB.prepare("SELECT 1 AS ok").first();
      return json({ ok: true, service: "Control de accesos", database: true });
    }

    if (path === "/api/admin/login" && request.method === "POST") return adminLogin(request, env);
    if (path === "/api/admin/logout" && request.method === "POST") return adminLogout();
    if (path === "/api/admin/data" && request.method === "GET") {
      if (!(await isAdmin(request, env))) return json({ error: "No autorizado" }, 401);
      return adminData(env);
    }
    if (path === "/api/admin/sites" && request.method === "POST") {
      if (!(await isAdmin(request, env))) return json({ error: "No autorizado" }, 401);
      return saveSite(request, env);
    }
    if (path === "/api/admin/visitor-name" && request.method === "POST") {
      if (!(await isAdmin(request, env))) return json({ error: "No autorizado" }, 401);
      return renameVisitor(request, env);
    }
    if (path === "/api/admin/site-status" && request.method === "POST") {
      if (!(await isAdmin(request, env))) return json({ error: "No autorizado" }, 401);
      return setSiteStatus(request, env);
    }

    if (path === "/api/consent" && request.method === "POST") return setConsent(request, env);
    if (path === "/api/consent/revoke" && request.method === "POST") return revokeConsent(request);
    if (path === "/api/leave" && request.method === "POST") return markLeave(request, env);

    if (path === "/go" || path.startsWith("/go/")) return handleGo(request, env, url);
    if (path === "/sitio" || path.startsWith("/sitio/")) return handleProtected(context, env, url);

    if (path === "/") return redirect(new URL("/admin/", url), 302);
    if (path === "/admin") return redirect(new URL("/admin/", url), 302);
    return context.next();
  } catch (error) {
    console.error("Control de accesos:", error);
    return new Response("Error interno del sistema de accesos. Revisa los registros de Pages Functions.", {
      status: 500,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }
    });
  }
}

async function handleGo(request, env, url) {
  if (request.method !== "GET") return new Response("Método no permitido", { status: 405 });
  let site = null;
  const pathSlug = url.pathname.startsWith("/go/") ? decodeURIComponent(url.pathname.slice(4).split("/")[0]) : "";
  if (pathSlug) {
    site = await env.DB.prepare("SELECT * FROM sites WHERE slug = ? AND active = 1").bind(pathSlug).first();
  } else {
    const target = url.searchParams.get("web");
    if (!target) return new Response("Falta el parámetro ?web= o el identificador del sitio.", { status: 400 });
    site = await env.DB.prepare("SELECT * FROM sites WHERE target_url = ? AND active = 1").bind(target).first();
  }
  if (!site) return new Response("Destino no registrado o desactivado. Añádelo desde el panel de administración.", { status: 404 });

  if (site.mode === "protected") {
    return redirect(new URL(`/sitio/${encodeURIComponent(site.slug)}/`, url), 302);
  }

  // En modo redirección el salto sigue siendo inmediato. Si ya existe consentimiento,
  // se asocia la visita al navegador; en caso contrario se guarda una visita anónima.
  await recordRedirectVisit(request, env, site, url);
  return redirect(site.target_url, 302);
}

async function handleProtected(context, env, url) {
  const { request } = context;
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Método no permitido", { status: 405 });
  }
  const parts = url.pathname.split("/").filter(Boolean);
  const slug = parts[1] || "";
  if (parts.length === 2 && !url.pathname.endsWith("/")) {
    url.pathname += "/";
    return redirect(url, 301);
  }
  if (!slug) return new Response("Falta el identificador del sitio.", { status: 404 });
  const site = await env.DB.prepare("SELECT * FROM sites WHERE slug = ? AND active = 1").bind(slug).first();
  if (!site || site.mode !== "protected") return new Response("Sitio protegido no disponible.", { status: 404 });

  const isDocument = request.method === "GET" && (request.headers.get("accept") || "").includes("text/html");
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const consent = cookies[CONSENT_COOKIE];
  let visitorId = consent === "accepted" ? (cookies[VISITOR_COOKIE] || "") : "";
  const sessionId = cookies[SESSION_COOKIE] || "";

  if (!visitorId && !sessionId && !isDocument) {
    return new Response("Abre primero la página principal del sitio protegido.", {
      status: 403,
      headers: { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" }
    });
  }

  let visitId = "";
  if (isDocument) {
    visitId = crypto.randomUUID();
    if (visitorId) {
      await upsertVisitor(request, env, visitorId, {});
    }
    await env.DB.prepare(`
      INSERT INTO access_logs (id, visitor_id, site_id, site_slug, accessed_at, path, access_mode, outcome)
      VALUES (?, ?, ?, ?, ?, ?, 'protected', 'allowed')
    `).bind(visitId, visitorId || null, site.id, site.slug, nowIso(), safePath(url)).run();
  }

  const response = await context.next();
  if (!isDocument || !response.headers.get("content-type")?.toLowerCase().includes("text/html")) return response;

  const script = buildPageScript({ visitId, slug: site.slug, showConsent: (!visitorId && consent !== "denied") });
  const transformed = new HTMLRewriter()
    .on("body", { element(element) { element.append(script, { html: true }); } })
    .transform(response);
  const headers = new Headers(transformed.headers);
  headers.set("cache-control", "private, no-store, max-age=0");
  headers.delete("content-length");
  headers.delete("content-encoding");
  if (!visitorId && !sessionId) {
    headers.append("set-cookie", `${SESSION_COOKIE}=${crypto.randomUUID()}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  }
  return new Response(transformed.body, { status: transformed.status, statusText: transformed.statusText, headers });
}

async function setConsent(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  let data;
  try { data = await request.json(); } catch { return json({ error: "JSON no válido" }, 400); }
  const visitId = String(data.visit_id || "");
  if (!/^[0-9a-f-]{36}$/i.test(visitId)) return json({ error: "Visita no válida" }, 400);
  const accepted = data.accepted === true;
  const headers = new Headers({ "cache-control": "no-store" });

  if (!accepted) {
    headers.append("set-cookie", `${CONSENT_COOKIE}=denied; Max-Age=${CONSENT_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Lax`);
    return json({ ok: true, accepted: false }, 200, headers);
  }

  const row = await env.DB.prepare("SELECT visitor_id FROM access_logs WHERE id = ? LIMIT 1").bind(visitId).first();
  if (!row) return json({ error: "Registro de visita no encontrado" }, 404);
  const visitorId = crypto.randomUUID();
  await upsertVisitor(request, env, visitorId, {
    timezone: cleanText(data.timezone, 80),
    language: cleanText(data.language, 80),
    screenSize: validScreen(data.screen)
  }, true);
  await env.DB.prepare("UPDATE access_logs SET visitor_id = ? WHERE id = ?").bind(visitorId, visitId).run();
  await env.DB.prepare("UPDATE visitors SET visits = visits + 1 WHERE visitor_id = ?").bind(visitorId).run();

  headers.append("set-cookie", `${CONSENT_COOKIE}=accepted; Max-Age=${CONSENT_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  headers.append("set-cookie", `${VISITOR_COOKIE}=${visitorId}; Max-Age=${VISITOR_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  return json({ ok: true, accepted: true }, 200, headers);
}

async function revokeConsent(request) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  const headers = new Headers({ "cache-control": "no-store" });
  headers.append("set-cookie", `${CONSENT_COOKIE}=denied; Max-Age=${CONSENT_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  headers.append("set-cookie", `${VISITOR_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`);
  return json({ ok: true }, 200, headers);
}

async function markLeave(request, env) {
  if (!sameOrigin(request)) return new Response(null, { status: 204 });
  let data;
  try { data = await request.json(); } catch { return new Response(null, { status: 204 }); }
  const visitId = String(data.visit_id || "");
  if (/^[0-9a-f-]{36}$/i.test(visitId)) {
    const cookies = parseCookies(request.headers.get("cookie") || "");
    const visitorId = cookies[VISITOR_COOKIE] || "";
    await env.DB.prepare(`UPDATE access_logs SET exited_at = ? WHERE id = ? AND (visitor_id = ? OR visitor_id IS NULL)`)
      .bind(nowIso(), visitId, visitorId).run();
  }
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function recordRedirectVisit(request, env, site, url) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const consentedId = cookies[CONSENT_COOKIE] === "accepted" ? (cookies[VISITOR_COOKIE] || "") : "";
  const logId = crypto.randomUUID();
  if (consentedId) await upsertVisitor(request, env, consentedId, {});
  await env.DB.prepare(`
    INSERT INTO access_logs (id, visitor_id, site_id, site_slug, accessed_at, path, access_mode, outcome)
    VALUES (?, ?, ?, ?, ?, ?, 'redirect', 'allowed')
  `).bind(logId, consentedId || null, site.id, site.slug, nowIso(), safePath(url)).run();
}

async function upsertVisitor(request, env, visitorId, extra = {}, isNew = false) {
  const now = nowIso();
  const ua = request.headers.get("user-agent") || "";
  const cf = request.cf || {};
  const device = parseDevice(ua);
  const ipHash = await hashIp(request.headers.get("cf-connecting-ip") || "", env.IP_HASH_SECRET || "");
  if (isNew) {
    await env.DB.prepare(`
      INSERT INTO visitors (
        visitor_id, first_seen, last_seen, visits, user_agent, browser, operating_system,
        device_type, country, region, city, timezone, language, screen_size, ip_hash, consented_at
      ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(visitor_id) DO UPDATE SET last_seen = excluded.last_seen
    `).bind(
      visitorId, now, now, ua.slice(0, 500), device.browser, device.os, device.type,
      cleanText(cf.country, 80), cleanText(cf.region, 120), cleanText(cf.city, 120),
      extra.timezone || cleanText(cf.timezone, 100), extra.language || cleanText(request.headers.get("accept-language"), 120),
      extra.screenSize || null, ipHash, now
    ).run();
    return;
  }
  await env.DB.prepare(`
    INSERT INTO visitors (
      visitor_id, first_seen, last_seen, visits, user_agent, browser, operating_system,
      device_type, country, region, city, timezone, language, ip_hash, consented_at
    ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(visitor_id) DO UPDATE SET
      last_seen = excluded.last_seen,
      user_agent = CASE WHEN excluded.user_agent != '' THEN excluded.user_agent ELSE visitors.user_agent END,
      browser = COALESCE(excluded.browser, visitors.browser),
      operating_system = COALESCE(excluded.operating_system, visitors.operating_system),
      device_type = COALESCE(excluded.device_type, visitors.device_type),
      country = COALESCE(excluded.country, visitors.country),
      region = COALESCE(excluded.region, visitors.region),
      city = COALESCE(excluded.city, visitors.city),
      timezone = COALESCE(excluded.timezone, visitors.timezone),
      language = COALESCE(excluded.language, visitors.language),
      ip_hash = COALESCE(excluded.ip_hash, visitors.ip_hash)
  `).bind(
    visitorId, now, now, ua.slice(0, 500), device.browser, device.os, device.type,
    cleanText(cf.country, 80), cleanText(cf.region, 120), cleanText(cf.city, 120),
    cleanText(cf.timezone, 100), cleanText(request.headers.get("accept-language"), 120), ipHash, now
  ).run();
  await env.DB.prepare("UPDATE visitors SET visits = visits + 1 WHERE visitor_id = ?").bind(visitorId).run();
}

async function adminLogin(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  if (!env.ADMIN_PASSWORD || !env.ADMIN_SESSION_SECRET) return json({ error: "Faltan ADMIN_PASSWORD y ADMIN_SESSION_SECRET en los secretos de Pages." }, 500);
  let data;
  try { data = await request.json(); } catch { return json({ error: "JSON no válido" }, 400); }
  const supplied = String(data.password || "");
  if (!constantTimeEqual(supplied, env.ADMIN_PASSWORD)) return json({ error: "Contraseña incorrecta" }, 401);
  const expires = Math.floor(Date.now() / 1000) + ADMIN_MAX_AGE;
  const payload = String(expires);
  const signature = await hmac(payload, env.ADMIN_SESSION_SECRET);
  const token = `${payload}.${signature}`;
  const headers = new Headers({ "cache-control": "no-store" });
  headers.append("set-cookie", `${ADMIN_COOKIE}=${token}; Max-Age=${ADMIN_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Strict`);
  return json({ ok: true }, 200, headers);
}

async function adminLogout() {
  const headers = new Headers({ "cache-control": "no-store" });
  headers.append("set-cookie", `${ADMIN_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`);
  return json({ ok: true }, 200, headers);
}

async function isAdmin(request, env) {
  if (!env.ADMIN_SESSION_SECRET) return false;
  const token = parseCookies(request.headers.get("cookie") || "")[ADMIN_COOKIE] || "";
  const [expiresText, signature] = token.split(".");
  const expires = Number(expiresText);
  if (!expires || expires < Math.floor(Date.now() / 1000) || !signature) return false;
  return constantTimeEqual(signature, await hmac(expiresText, env.ADMIN_SESSION_SECRET));
}

async function adminData(env) {
  const today = await env.DB.prepare("SELECT COUNT(*) AS n FROM access_logs WHERE date(accessed_at) = date('now')").first();
  const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM access_logs").first();
  const unique = await env.DB.prepare("SELECT COUNT(*) AS n FROM visitors").first();
  const sites = await env.DB.prepare("SELECT * FROM sites ORDER BY name COLLATE NOCASE").all();
  const recent = await env.DB.prepare(`
    SELECT l.id, l.site_slug, s.name AS site_name, l.accessed_at, l.exited_at, l.path,
           l.access_mode, l.outcome, l.visitor_id, COALESCE(v.nickname, substr(l.visitor_id,1,13), 'Anónimo') AS visitor_name,
           v.browser, v.operating_system, v.device_type, v.country, v.city
    FROM access_logs l
    LEFT JOIN visitors v ON v.visitor_id = l.visitor_id
    LEFT JOIN sites s ON s.id = l.site_id
    ORDER BY l.accessed_at DESC LIMIT 100
  `).all();
  const visitors = await env.DB.prepare(`
    SELECT visitor_id, nickname, first_seen, last_seen, visits, browser, operating_system,
           device_type, country, region, city, timezone, language, screen_size
    FROM visitors ORDER BY last_seen DESC LIMIT 200
  `).all();
  return json({
    stats: { today: today?.n || 0, total: total?.n || 0, visitors: unique?.n || 0 },
    sites: sites.results || [], recent: recent.results || [], visitors: visitors.results || []
  });
}

async function saveSite(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  let data;
  try { data = await request.json(); } catch { return json({ error: "JSON no válido" }, 400); }
  const slug = String(data.slug || "").trim().toLowerCase();
  const name = cleanText(data.name, 100);
  const target = String(data.target_url || "").trim();
  const mode = String(data.mode || "");
  const active = data.active === false ? 0 : 1;
  if (!/^[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?$/.test(slug)) return json({ error: "Identificador no válido: usa letras minúsculas, números y guiones." }, 400);
  if (!name) return json({ error: "Escribe un nombre para el sitio." }, 400);
  if (!['redirect', 'protected'].includes(mode)) return json({ error: "Modo no válido." }, 400);
  let parsed;
  try { parsed = new URL(target); } catch { return json({ error: "URL no válida." }, 400); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) return json({ error: "La URL debe ser HTTPS y no incluir credenciales." }, 400);
  try {
    await env.DB.prepare(`
      INSERT INTO sites (id, slug, name, target_url, mode, active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(slug) DO UPDATE SET
        name = excluded.name, target_url = excluded.target_url, mode = excluded.mode,
        active = excluded.active, updated_at = excluded.updated_at
    `).bind(`site_${slug}`, slug, name, parsed.href, mode, active, nowIso(), nowIso()).run();
  } catch (error) {
    return json({ error: "No se pudo guardar. Comprueba que esa URL no esté asignada a otro sitio." }, 409);
  }
  return json({ ok: true });
}

async function setSiteStatus(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  let data;
  try { data = await request.json(); } catch { return json({ error: "JSON no válido" }, 400); }
  const slug = String(data.slug || "");
  if (!/^[a-z0-9-]{2,50}$/.test(slug)) return json({ error: "Identificador no válido." }, 400);
  await env.DB.prepare("UPDATE sites SET active = ?, updated_at = ? WHERE slug = ?")
    .bind(data.active === true ? 1 : 0, nowIso(), slug).run();
  return json({ ok: true });
}

async function renameVisitor(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origen no válido" }, 403);
  let data;
  try { data = await request.json(); } catch { return json({ error: "JSON no válido" }, 400); }
  const id = String(data.visitor_id || "");
  const nickname = cleanText(data.nickname, 80);
  if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Dispositivo no válido." }, 400);
  await env.DB.prepare("UPDATE visitors SET nickname = ? WHERE visitor_id = ?").bind(nickname || null, id).run();
  return json({ ok: true });
}

function buildPageScript({ visitId, slug, showConsent }) {
  const visit = JSON.stringify(visitId);
  const site = JSON.stringify(slug);
  const consentUi = showConsent ? `
    const box=document.createElement('div');
    box.id='ca-consent-box';
    box.style.cssText='position:fixed;z-index:2147483647;left:16px;right:16px;bottom:16px;max-width:560px;margin:auto;padding:16px;background:#111827;color:#fff;border:1px solid #475569;border-radius:14px;box-shadow:0 12px 40px #0006;font:14px/1.45 system-ui,sans-serif';
    box.innerHTML='<strong>Control de accesos</strong><p style="margin:7px 0 12px">Este sitio puede guardar un identificador aleatorio de este navegador y datos técnicos (navegador, sistema, idioma y ubicación aproximada) para reconocer visitas. No identifica tu nombre real. Puedes aceptar o rechazar este seguimiento.</p><div style="display:flex;gap:8px;flex-wrap:wrap"><button id="ca-yes" style="padding:9px 13px;border:0;border-radius:8px;background:#38bdf8;color:#082f49;font-weight:700">Aceptar</button><button id="ca-no" style="padding:9px 13px;border:1px solid #94a3b8;border-radius:8px;background:transparent;color:#fff">Rechazar</button><a href="/privacidad.html" style="padding:9px;color:#cbd5e1">Privacidad</a></div>';
    document.body.appendChild(box);
    async function choose(accepted){
      const data={visit_id:VISIT_ID,accepted,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'',language:navigator.language||'',screen:(screen.width||0)+'x'+(screen.height||0)};
      const r=await fetch('/api/consent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data),credentials:'same-origin'});
      if(r.ok){box.remove();}
    }
    box.querySelector('#ca-yes').addEventListener('click',()=>choose(true));
    box.querySelector('#ca-no').addEventListener('click',()=>choose(false));
  ` : "";
  return `<script>(()=>{const VISIT_ID=${visit};const SITE=${site};${consentUi}
    window.addEventListener('pagehide',()=>{try{navigator.sendBeacon('/api/leave',new Blob([JSON.stringify({visit_id:VISIT_ID,site:SITE})],{type:'application/json'}));}catch(e){}},{once:true});
  })();</script>`;
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

function parseDevice(ua) {
  const s = ua.toLowerCase();
  let browser = "Desconocido";
  if (s.includes("edg/")) browser = "Microsoft Edge";
  else if (s.includes("opr/") || s.includes("opera")) browser = "Opera";
  else if (s.includes("firefox/")) browser = "Firefox";
  else if (s.includes("chrome/") && !s.includes("edg/")) browser = "Chrome";
  else if (s.includes("safari/") && !s.includes("chrome/")) browser = "Safari";
  let os = "Desconocido";
  if (s.includes("windows")) os = "Windows";
  else if (s.includes("iphone") || s.includes("ipad") || s.includes("ios")) os = "iOS";
  else if (s.includes("android")) os = "Android";
  else if (s.includes("mac os x") || s.includes("macintosh")) os = "macOS";
  else if (s.includes("linux")) os = "Linux";
  let type = "Ordenador";
  if (s.includes("ipad") || s.includes("tablet")) type = "Tableta";
  else if (s.includes("mobile") || s.includes("iphone") || s.includes("android")) type = "Móvil";
  return { browser, os, type };
}

async function hashIp(ip, secret) {
  if (!ip || !secret) return null;
  return hmac(ip, secret);
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(signature));
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);
  for (let i = 0; i < length; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function sameOrigin(request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

function cleanText(value, max) {
  if (value == null) return null;
  const s = String(value).replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return s ? s.slice(0, max) : null;
}

function validScreen(value) {
  const s = String(value || "");
  return /^\d{1,5}x\d{1,5}$/.test(s) ? s : null;
}

function safePath(url) {
  return (url.pathname + url.search).slice(0, 1000);
}

function nowIso() {
  return new Date().toISOString();
}

function redirect(location, status = 302) {
  return new Response(null, { status, headers: { location: String(location), "cache-control": "no-store" } });
}

function json(data, status = 200, headers = new Headers()) {
  const h = new Headers(headers);
  h.set("content-type", "application/json; charset=utf-8");
  h.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { status, headers: h });
}
