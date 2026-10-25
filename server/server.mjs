// Next Step — Forum DSI kiosk backend
// Serves the kiosk, proxies SAFE aggregate leak lookups to Elasticsearch,
// persists leads + event logs to disk, and powers the super-admin dashboard.
//
// Design rules:
//   - The Elasticsearch URL lives here, server-side. It is NEVER sent to the browser.
//   - /api/leak-check returns ONLY aggregates + masked samples. Plaintext passwords
//     are never requested from ES and never leave this process.
//   - A domain lookup requires an explicit "authorized" flag (the kiosk consent box).
//   - /api/admin/* is gated by a session token obtained via /api/admin/login
//     (username + password; defaults ADMIN_USER / ADMIN_PASS, changeable from the dashboard).
import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";
import { timingSafeEqual, randomBytes, scryptSync } from "node:crypto";
import { connectDb, closeDb, saveLead, saveEvent, getRecentLeads, getRecentEvents, getAllLeads, getAllEvents, getSettings, saveSettings } from "./db.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");

const CFG = {
  port: Number(process.env.PORT || 8080),
  host: process.env.HOST || "0.0.0.0",
  esUrl: (process.env.ES_URL || "http://10.9.21.32:9200").replace(/\/+$/, ""),
  esIndex: process.env.ES_INDEX || "leaks_data",
  esUser: process.env.ES_USER || "",
  esPass: process.env.ES_PASS || "",
  esTimeoutMs: Number(process.env.ES_TIMEOUT_MS || 20000),
  rateMax: Number(process.env.RATE_MAX || 20),
  rateWindowMs: Number(process.env.RATE_WINDOW_MS || 60000),
  // Default super-admin credentials. Change them from the dashboard (stored hashed in Mongo)
  // or set ADMIN_USER / ADMIN_PASS in the environment.
  adminUser: process.env.ADMIN_USER || "superadmin",
  adminPass: process.env.ADMIN_PASS || "Admin@2026", // keep in sync with DEFAULT_ADMIN_PASS
  sessionTtlMs: Number(process.env.ADMIN_SESSION_HOURS || 12) * 3600 * 1000,
  // Data source for leak lookups + posture scans: "elastic" (default) or "scanbe4".
  leakSource: process.env.LEAK_SOURCE || "elastic",
  sb4LeaksUrl: process.env.SB4_LEAKS_URL || "https://scanbe4.com/api/v1/leaks",
  sb4ScanUrl: process.env.SB4_SCAN_URL || "https://scanbe4.com/api/v1/scans",
  sb4Token: process.env.SB4_TOKEN || "",
};

// Effective data-source config: environment defaults, overridden by values saved
// from the super-admin dashboard (stored in Mongo). Non-empty stored values win.
function effective() {
  const s = getSettings() || {};
  const sb4 = s.sb4 || {};
  return {
    leakSource: s.leakSource || CFG.leakSource,
    esUrl: (s.esUrl || CFG.esUrl).replace(/\/+$/, ""),
    esIndex: s.esIndex || CFG.esIndex,
    esUser: s.esUser ?? CFG.esUser, esPass: s.esPass ?? CFG.esPass,
    sb4LeaksUrl: (sb4.leaksUrl || CFG.sb4LeaksUrl || "").replace(/\/+$/, ""),
    sb4ScanUrl: (sb4.scanUrl || CFG.sb4ScanUrl || "").replace(/\/+$/, ""),
    sb4Token: sb4.token || CFG.sb4Token || "",
  };
}

/* ---------- labels (mirror the kiosk) ---------- */
const GOAL_LABEL = { sup:"Supervision 24/7", resp:"Réponse aux incidents", hunt:"Threat hunting",
  vuln:"Gestion des vulnérabilités", aware:"Sensibilisation", pentest:"Tests d'intrusion",
  gov:"Gouvernance & conformité", exec:"Reporting risque direction" };
const SERV_LABEL = { iaas:"Hébergement (IaaS)", backup:"Sauvegarde externalisée", dr:"Plan de reprise (DRaaS)",
  paas:"Conteneurs managés", mail:"Messagerie hébergée", s3:"Stockage objet", housing:"Housing / colocation" };
const EPP_LABEL = { "3":"< 3 mois", "6":"3 à 6 mois", "12":"6 à 12 mois", later:"> 12 mois", none:"Sans EPP" };
const INFRA_LABEL = { "3":"< 3 mois", "6":"3 à 6 mois", "12":"6 à 12 mois", later:"> 12 mois", none:"Aucune" };

/* ---------- helpers ---------- */
const MIME = { ".html":"text/html; charset=utf-8", ".js":"text/javascript", ".css":"text/css",
  ".png":"image/png", ".svg":"image/svg+xml", ".ico":"image/x-icon", ".json":"application/json" };

const esHeaders = (eff) => {
  const h = { "Content-Type": "application/json" };
  if (eff.esUser) h.Authorization = "Basic " + Buffer.from(`${eff.esUser}:${eff.esPass}`).toString("base64");
  return h;
};

async function esSearch(body, eff = effective()) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), CFG.esTimeoutMs);
  try {
    const r = await fetch(`${eff.esUrl}/${encodeURIComponent(eff.esIndex)}/_search`, {
      method: "POST", headers: esHeaders(eff), body: JSON.stringify(body), signal: ctl.signal,
    });
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error ? JSON.stringify(j.error).slice(0, 300) : `ES ${r.status}`);
    return j;
  } finally { clearTimeout(timer); }
}

// Fetch with a timeout (used for the ScanBe4 HTTP API).
async function fetchJson(url, opts = {}, timeoutMs = CFG.esTimeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal });
    let j = null; try { j = await r.json(); } catch {}
    return { ok: r.ok, status: r.status, json: j };
  } finally { clearTimeout(timer); }
}

function cleanDomain(input) {
  const d = String(input || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d) ? d : null;
}

function maskLogin(s) {
  s = String(s || "");
  if (s.includes("@")) {
    const [u, dom] = s.split("@");
    const head = u.slice(0, Math.min(2, u.length));
    return `${head}${"•".repeat(Math.max(3, u.length - head.length))}@${dom}`;
  }
  if (s.length <= 3) return s[0] ? s[0] + "••" : "•••";
  return s.slice(0, 2) + "•".repeat(Math.max(3, s.length - 2));
}

function send(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

function readBody(req, maxBytes = 16384) {
  return new Promise((resolve, reject) => {
    let raw = "", size = 0;
    req.on("data", c => { size += c.length; if (size > maxBytes) { req.destroy(); reject(new Error("too large")); } raw += c; });
    req.on("end", () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}

/* ---------- super-admin auth ---------- */
const safeEq = (x, y) => { const a = Buffer.from(String(x)), b = Buffer.from(String(y)); return a.length === b.length && timingSafeEqual(a, b); };
const hashPass = (pass, salt) => scryptSync(String(pass), salt, 64).toString("hex");

// Credentials saved from the dashboard win over the environment defaults.
function checkCredentials(user, pass) {
  const saved = getSettings().admin;
  if (saved?.user && saved?.hash && saved?.salt) {
    return safeEq(user, saved.user) && safeEq(hashPass(pass, saved.salt), saved.hash);
  }
  return safeEq(user, CFG.adminUser) && safeEq(pass, CFG.adminPass);
}
const adminUser = () => getSettings().admin?.user || CFG.adminUser;
const DEFAULT_ADMIN_PASS = "Admin@2026";
const usingDefaultCreds = () => !getSettings().admin?.hash && CFG.adminPass === DEFAULT_ADMIN_PASS;

// In-memory sessions: token -> expiry. A server restart logs everyone out.
const sessions = new Map();
function newSession() {
  const token = randomBytes(32).toString("hex");
  sessions.set(token, Date.now() + CFG.sessionTtlMs);
  return token;
}
function sessionToken(req) {
  const h = req.headers["authorization"] || "";
  return h.startsWith("Bearer ") ? h.slice(7) : (new URL(req.url, "http://x").searchParams.get("token") || "");
}
function adminOk(req) {
  const token = sessionToken(req), exp = sessions.get(token);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(token); return false; }
  return true;
}

// Brute-force protection for the login form: 10 failures per IP per 15 min.
const loginFails = new Map();
function loginBlocked(ip) {
  const now = Date.now(), arr = (loginFails.get(ip) || []).filter(t => now - t < 15 * 60000);
  loginFails.set(ip, arr);
  return arr.length >= 10;
}

/* ---------- rate limiting ---------- */
const hits = new Map();
function rateOk(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < CFG.rateWindowMs);
  if (arr.length >= CFG.rateMax) { hits.set(ip, arr); return false; }
  arr.push(now); hits.set(ip, arr); return true;
}

/* ---------- leak lookup: dispatcher ---------- */
async function leakLookup(domain) {
  const eff = effective();
  if (eff.leakSource === "scanbe4") {
    if (!eff.sb4LeaksUrl || !eff.sb4Token) throw new Error("ScanBe4 non configuré (URL ou jeton manquant).");
    return leakCheckScanbe4(domain, eff);
  }
  return leakCheckES(domain, eff);
}

/* ---------- leak lookup: ScanBe4 API ---------- */
async function leakCheckScanbe4(domain, eff) {
  const url = `${eff.sb4LeaksUrl}?domain=${encodeURIComponent(domain)}&limit=200`;
  const { ok, status, json } = await fetchJson(url, { headers: { Authorization: `Bearer ${eff.sb4Token}` } });
  if (!ok || !json) throw new Error(`ScanBe4 ${status}`);
  const recs = Array.isArray(json.records) ? json.records : [];
  const total = Number.isFinite(json.total) ? json.total : recs.length;

  const sites = new Map(), countries = new Map(), years = new Map(), accounts = new Set();
  let latest = null;
  for (const x of recs) {
    const site = x.website || x.url_domain || null;
    if (site) sites.set(site, (sites.get(site) || 0) + 1);
    if (x.country) countries.set(x.country, (countries.get(x.country) || 0) + 1);
    const acct = String(x.email || x.username || "").toLowerCase();
    if (acct) accounts.add(acct);
    const ts = x.timestamp ? String(x.timestamp) : null;
    if (ts) { years.set(ts.slice(0, 4), (years.get(ts.slice(0, 4)) || 0) + 1); if (!latest || ts > latest) latest = ts; }
  }
  const top = (m, n) => [...m.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, n);

  return {
    domain, total, source: "scanbe4",
    sampled: recs.length < total, sampleSize: recs.length,
    accounts: accounts.size,
    identity: { records: 0, accounts: 0 },
    service: { records: total, accounts: accounts.size },
    topServices: top(sites, 8),
    countries: top(countries, 6),
    software: [],
    timeline: [...years.entries()].sort().map(([year, count]) => ({ year, count })),
    latest: latest ? latest.slice(0, 10) : null,
    samples: recs.slice(0, 5).map(x => ({
      login: maskLogin(x.email || x.username || ""),
      service: x.website || x.url || null,
      country: x.country || null,
      date: x.timestamp ? String(x.timestamp).slice(0, 10) : null,
    })),
  };
}

/* ---------- leak lookup: Elasticsearch ---------- */
async function leakCheckES(domain, eff) {
  const serviceFilter = { bool: { should: [
    { term: { "url_domain.keyword": domain } },
    { wildcard: { "url_domain.keyword": { value: `*.${domain}` } } },
  ], minimum_should_match: 1 } };

  const agg = await esSearch({
    size: 0, track_total_hits: true,
    query: { bool: { should: [ { term: { domain } }, serviceFilter ], minimum_should_match: 1 } },
    aggs: {
      identity: { filter: { term: { domain } }, aggs: { accounts: { cardinality: { field: "login" } } } },
      service: { filter: serviceFilter, aggs: { accounts: { cardinality: { field: "login" } } } },
      top_services: { filter: { term: { domain } }, aggs: { s: { terms: { field: "url_domain.keyword", size: 8 } } } },
      countries: { terms: { field: "country", size: 6 } },
      software: { terms: { field: "soft", size: 6 } },
      over_time: { date_histogram: { field: "timestamp", calendar_interval: "year", min_doc_count: 1 } },
      latest: { max: { field: "timestamp" } },
    },
  }, eff);

  let samples = [];
  const identityTotal = agg.aggregations?.identity?.doc_count || 0;
  if (identityTotal > 0) {
    const s = await esSearch({
      size: 5, _source: ["login", "url_domain", "country", "timestamp"],
      query: { term: { domain } }, sort: [{ timestamp: { order: "desc" } }],
    }, eff);
    samples = (s.hits?.hits || []).map(h => ({
      login: maskLogin(h._source?.login), service: h._source?.url_domain || null,
      country: h._source?.country || null,
      date: h._source?.timestamp ? String(h._source.timestamp).slice(0, 10) : null,
    }));
  }

  const a = agg.aggregations || {};
  return {
    domain, total: agg.hits?.total?.value || 0, source: "elastic",
    accounts: (a.identity?.accounts?.value || 0) + (a.service?.accounts?.value || 0),
    identity: { records: a.identity?.doc_count || 0, accounts: a.identity?.accounts?.value || 0 },
    service:  { records: a.service?.doc_count  || 0, accounts: a.service?.accounts?.value  || 0 },
    topServices: (a.top_services?.s?.buckets || []).map(b => ({ name: b.key, count: b.doc_count })),
    countries:   (a.countries?.buckets || []).map(b => ({ name: b.key, count: b.doc_count })),
    software:    (a.software?.buckets || []).map(b => ({ name: b.key, count: b.doc_count })),
    timeline:    (a.over_time?.buckets || []).map(b => ({ year: String(b.key_as_string || "").slice(0, 4), count: b.doc_count })),
    latest: a.latest?.value_as_string ? String(a.latest.value_as_string).slice(0, 10) : null,
    samples,
  };
}

/* ---------- statistics ---------- */
const topN = (map, n = 12) => [...map.entries()].map(([name, count]) => ({ name, count }))
  .sort((x, y) => y.count - x.count).slice(0, n);

function computeStats(leads, events) {
  const bump = (m, k) => { if (k == null || k === "") return; m.set(k, (m.get(k) || 0) + 1); };
  const domainsMix = new Map(), offers = new Map(), goals = new Map(), services = new Map(),
    sectors = new Map(), roles = new Map(), epp = new Map(), infra = new Map();
  let epSum = 0, epCount = 0, epMax = 0;

  for (const l of leads) {
    const d = l.domains || [];
    bump(domainsMix, d.length >= 2 ? "SOC + Cloud" : d[0] === "soc" ? "SOC seul" : d[0] === "cloud" ? "Cloud seul" : (l.leak ? "Vérif. fuites" : l.scan ? "Analyse posture" : "—"));
    bump(roles, l.contact?.role); bump(sectors, l.contact?.sector);
    if (l.soc) {
      bump(offers, l.soc.offered);
      (l.soc.goals || []).forEach(g => bump(goals, GOAL_LABEL[g] || g));
      bump(epp, EPP_LABEL[l.soc.epp] || null);
      const e = Number(l.soc.endpoints || 0); if (e) { epSum += e; epCount++; epMax = Math.max(epMax, e); }
    }
    if (l.cloud) { (l.cloud.services || []).forEach(s => bump(services, SERV_LABEL[s] || s)); bump(infra, INFRA_LABEL[l.cloud.renew] || null); }
  }

  // event-driven: feature popularity, funnel, timing
  const starts = new Map(), views = new Map(), byHour = Array(24).fill(0), byDay = new Map();
  let leakChecks = 0, leakHits = 0, leakAccounts = 0, scanReq = 0, completes = 0;
  const leakDomains = new Map();
  for (const ev of events) {
    const t = ev.ts ? new Date(ev.ts) : null;
    if (t && !isNaN(t)) { byHour[t.getHours()]++; const day = t.toISOString().slice(0, 10); byDay.set(day, (byDay.get(day) || 0) + 1); }
    if (ev.type === "start") bump(starts, ev.detail?.mode);
    if (ev.type === "view") bump(views, ev.detail?.screen);
    if (ev.type === "scan_requested") scanReq++;
    if (ev.type === "complete") completes++;
    if (ev.type === "leak_checked") {
      leakChecks++; if (ev.detail?.hit) leakHits++;
      leakAccounts += Number(ev.detail?.accounts || 0);
      if (ev.detail?.domain) leakDomains.set(ev.detail.domain, (leakDomains.get(ev.detail.domain) || 0) + 1);
    }
  }

  const startObj = { pack: starts.get("pack") || 0, scan: starts.get("scan") || 0, leak: starts.get("leak") || 0 };
  return {
    generatedAt: new Date().toISOString(),
    totals: {
      leads: leads.length, events: events.length,
      offers: leads.filter(l => l.soc).length,
      cloud: leads.filter(l => l.cloud).length,
      scans: leads.filter(l => l.scan).length + scanReq,
      leaks: leakChecks,
      completed: completes,
    },
    starts: startObj,
    funnel: {
      accueil: views.get("home") || 0,
      coordonnées: views.get("contact") || 0,
      besoins: views.get("needs") || 0,
      offre: views.get("result") || 0,
      "vérif. fuites": views.get("leakResult") || 0,
      analyse: views.get("scanDone") || 0,
    },
    domainsMix: topN(domainsMix), offers: topN(offers), goals: topN(goals), services: topN(services),
    sectors: topN(sectors), roles: topN(roles), eppUrgency: topN(epp), infraUrgency: topN(infra),
    endpoints: { avg: epCount ? Math.round(epSum / epCount) : 0, max: epMax, samples: epCount },
    leakStats: {
      checks: leakChecks, withExposure: leakHits,
      exposureRate: leakChecks ? Math.round(leakHits / leakChecks * 100) : 0,
      avgAccounts: leakHits ? Math.round(leakAccounts / leakHits) : 0,
      topDomains: topN(leakDomains, 10),
    },
    byHour, byDay: [...byDay.entries()].sort().map(([date, count]) => ({ date, count })),
  };
}

function leadsToCsv(leads) {
  const head = ["reference","date","nom","fonction","organisation","secteur","email","telephone","domaines","endpoints","pack_besoin","pack_offert","echeance_epp","vcpu","ram_go","ssd_go","services_cloud","produits_cloud","echeance_infra","domaine_analyse","statut_analyse","fuite_domaine","fuite_total","fuite_comptes"];
  const q = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const rows = leads.map(l => [l.ref, l.createdAt, l.contact?.name, l.contact?.role, l.contact?.company, l.contact?.sector,
    l.contact?.email, l.contact?.phone, (l.domains || []).join("+"), l.soc?.endpoints, l.soc?.recommended, l.soc?.offered,
    EPP_LABEL[l.soc?.epp] || "", l.soc?.nCloud?.vcpu, l.soc?.nCloud?.ramGo, l.soc?.nCloud?.ssdGo,
    (l.cloud?.services || []).join("+"), (l.cloud?.products || []).join(" | "), INFRA_LABEL[l.cloud?.renew] || "",
    l.scan?.domain, l.scan?.status, l.leak?.domain, l.leak?.total, l.leak?.accounts].map(q).join(";"));
  return "﻿" + [head.join(";"), ...rows].join("\r\n");
}

/* ---------- http ---------- */
async function serveStatic(req, res) {
  let path = decodeURIComponent((req.url || "/").split("?")[0]);
  if (path === "/") path = "/index.html";
  if (/^\/super-?admin\/?$/i.test(path)) path = "/superadmin.html";
  const full = normalize(join(PUBLIC_DIR, path));
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403).end("forbidden"); return; }
  try {
    const data = await readFile(full);
    res.writeHead(200, { "Content-Type": MIME[extname(full)] || "application/octet-stream" });
    res.end(data);
  } catch { res.writeHead(404, { "Content-Type": "text/plain" }).end("not found"); }
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString().split(",")[0].trim();
  const url = req.url || "/";

  try {
    if (req.method === "GET" && url === "/api/health") {
      const eff = effective();
      try {
        if (eff.leakSource === "scanbe4") {
          if (!eff.sb4LeaksUrl || !eff.sb4Token) return send(res, 200, { ok: false, source: "scanbe4", error: "non configuré" });
          const { ok, status } = await fetchJson(`${eff.sb4LeaksUrl}?domain=example.com&limit=1`, { headers: { Authorization: `Bearer ${eff.sb4Token}` } });
          return send(res, 200, { ok, source: "scanbe4", status });
        }
        await esSearch({ size: 0, terminate_after: 1 }, eff);
        return send(res, 200, { ok: true, source: "elastic", index: eff.esIndex });
      } catch (e) { return send(res, 200, { ok: false, source: eff.leakSource, error: String(e.message || e) }); }
    }

    // --- analytics event ---
    if (req.method === "POST" && url === "/api/event") {
      let b; try { b = await readBody(req, 8192); } catch { return send(res, 400, { error: "bad" }); }
      const type = String(b.type || "").slice(0, 40);
      if (!type) return send(res, 400, { error: "type requis" });
      await saveEvent({ ts: Number(b.ts) || Date.now(), type, ref: b.ref ? String(b.ref).slice(0, 40) : null,
        detail: b.detail && typeof b.detail === "object" ? b.detail : {}, ip });
      return send(res, 200, { ok: true });
    }

    // --- persist a lead ---
    if (req.method === "POST" && url === "/api/lead") {
      let b; try { b = await readBody(req, 32768); } catch { return send(res, 400, { error: "bad" }); }
      if (!b || !b.ref) return send(res, 400, { error: "lead invalide" });
      await saveLead({ ...b, _ip: ip });
      await saveEvent({ ts: Date.now(), type: "lead_saved", ref: String(b.ref).slice(0, 40), detail: { mode: b.mode, domains: b.domains || [] }, ip });
      return send(res, 200, { ok: true });
    }

    // --- leak lookup ---
    if (req.method === "POST" && url === "/api/leak-check") {
      if (!rateOk(ip)) return send(res, 429, { error: "Trop de requêtes, patientez un instant." });
      let b; try { b = await readBody(req, 4096); } catch { return send(res, 400, { error: "JSON invalide." }); }
      const domain = cleanDomain(b.domain);
      if (!domain) return send(res, 400, { error: "Domaine invalide." });
      if (b.authorized !== true) return send(res, 403, { error: "Autorisation requise pour analyser ce domaine." });
      try {
        const result = await leakLookup(domain);
        await saveEvent({ ts: Date.now(), type: "leak_checked", ref: b.ref ? String(b.ref).slice(0, 40) : null,
          detail: { domain, hit: result.total > 0, total: result.total, accounts: result.accounts ?? ((result.identity?.accounts||0) + (result.service?.accounts||0)), source: result.source }, ip });
        return send(res, 200, result);
      } catch (e) {
        console.error("[leak-check]", domain, String(e.message || e));
        return send(res, 502, { error: "Service de recherche indisponible pour le moment." });
      }
    }

    // --- trigger a ScanBe4 posture scan ---
    if (req.method === "POST" && url === "/api/scan") {
      if (!rateOk(ip)) return send(res, 429, { error: "Trop de requêtes, patientez un instant." });
      let b; try { b = await readBody(req, 4096); } catch { return send(res, 400, { error: "JSON invalide." }); }
      const domain = cleanDomain(b.domain);
      if (!domain) return send(res, 400, { error: "Domaine invalide." });
      if (b.authorized !== true) return send(res, 403, { error: "Autorisation requise pour analyser ce domaine." });
      const eff = effective();
      if (!eff.sb4ScanUrl || !eff.sb4Token) return send(res, 200, { ok: true, queued: false, note: "scan externe non configuré" });
      try {
        const email = String(b.email || "").slice(0, 160);
        const { ok, status, json } = await fetchJson(eff.sb4ScanUrl, {
          method: "POST", headers: { Authorization: `Bearer ${eff.sb4Token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ domain, authorized: true, mode: b.mode === "light" ? "light" : "full", notify_email: email || undefined }),
        });
        await saveEvent({ ts: Date.now(), type: "scan_requested", ref: b.ref ? String(b.ref).slice(0, 40) : null,
          detail: { domain, ok, status, scanId: json?.id || json?.scan_id || null }, ip });
        if (!ok) return send(res, 502, { error: "Lancement de l'analyse indisponible pour le moment." });
        return send(res, 200, { ok: true, queued: true, id: json?.id || json?.scan_id || null });
      } catch (e) {
        console.error("[scan]", domain, String(e.message || e));
        return send(res, 502, { error: "Lancement de l'analyse indisponible pour le moment." });
      }
    }

    // --- super-admin login ---
    if (req.method === "POST" && url === "/api/admin/login") {
      if (loginBlocked(ip)) return send(res, 429, { error: "Trop de tentatives, réessayez dans 15 minutes." });
      let b; try { b = await readBody(req, 2048); } catch { return send(res, 400, { error: "bad" }); }
      if (!checkCredentials(b.user || "", b.pass || "")) {
        loginFails.get(ip).push(Date.now());
        await saveEvent({ ts: Date.now(), type: "admin_login_failed", ref: null, detail: { user: String(b.user || "").slice(0, 60) }, ip });
        return send(res, 401, { error: "Identifiants invalides." });
      }
      loginFails.delete(ip);
      await saveEvent({ ts: Date.now(), type: "admin_login", ref: null, detail: { user: adminUser() }, ip });
      return send(res, 200, { ok: true, token: newSession(), user: adminUser(), defaultCreds: usingDefaultCreds() });
    }

    // --- admin API (session-gated) ---
    if (url.startsWith("/api/admin/")) {
      if (!adminOk(req)) return send(res, 401, { error: "Session invalide ou expirée." });
      const path = url.split("?")[0];
      if (path === "/api/admin/logout" && req.method === "POST") {
        sessions.delete(sessionToken(req));
        return send(res, 200, { ok: true });
      }
      if (path === "/api/admin/me") {
        return send(res, 200, { user: adminUser(), defaultCreds: usingDefaultCreds() });
      }
      // --- change super-admin credentials ---
      if (path === "/api/admin/credentials" && req.method === "POST") {
        let b; try { b = await readBody(req, 2048); } catch { return send(res, 400, { error: "bad" }); }
        if (!checkCredentials(adminUser(), b.current || "")) return send(res, 403, { error: "Mot de passe actuel incorrect." });
        const user = String(b.user || adminUser()).trim().slice(0, 60);
        const pass = String(b.pass || "");
        if (!user) return send(res, 400, { error: "Identifiant requis." });
        if (pass.length < 8) return send(res, 400, { error: "Le mot de passe doit faire au moins 8 caractères." });
        const salt = randomBytes(16).toString("hex");
        await saveSettings({ admin: { user, salt, hash: hashPass(pass, salt) } });
        // Invalidate every other session; keep the current one.
        const keep = sessionToken(req);
        for (const t of sessions.keys()) if (t !== keep) sessions.delete(t);
        await saveEvent({ ts: Date.now(), type: "admin_credentials_changed", ref: null, detail: { user }, ip });
        return send(res, 200, { ok: true, user });
      }
      if (path === "/api/admin/stats") {
        const [leads, events] = await Promise.all([getAllLeads(), getAllEvents()]);
        return send(res, 200, computeStats(leads, events));
      }
      if (path === "/api/admin/leads") {
        return send(res, 200, { leads: await getRecentLeads(500) });
      }
      if (path === "/api/admin/events") {
        return send(res, 200, { events: await getRecentEvents(800) });
      }
      if (path === "/api/admin/export.csv") {
        const leads = await getAllLeads();
        res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="leads-forum-dsi-${new Date().toISOString().slice(0,10)}.csv"` });
        return res.end(leadsToCsv(leads));
      }
      // --- data-source settings ---
      if (path === "/api/admin/settings" && req.method === "GET") {
        const eff = effective(); const s = getSettings() || {};
        const mask = t => t ? "••••" + String(t).slice(-4) : "";
        return send(res, 200, {
          leakSource: eff.leakSource,
          sb4: { leaksUrl: (s.sb4?.leaksUrl) || CFG.sb4LeaksUrl, scanUrl: (s.sb4?.scanUrl) || CFG.sb4ScanUrl,
                 tokenSet: !!eff.sb4Token, tokenHint: mask(eff.sb4Token) },
          es: { url: eff.esUrl, index: eff.esIndex, user: eff.esUser, passSet: !!eff.esPass },
        });
      }
      if (path === "/api/admin/settings" && req.method === "POST") {
        let b; try { b = await readBody(req, 8192); } catch { return send(res, 400, { error: "bad" }); }
        const patch = {};
        if (b.leakSource === "scanbe4" || b.leakSource === "elastic") patch.leakSource = b.leakSource;
        if (typeof b.esUrl === "string") patch.esUrl = b.esUrl.trim();
        if (typeof b.esIndex === "string") patch.esIndex = b.esIndex.trim();
        if (typeof b.esUser === "string") patch.esUser = b.esUser.trim();
        // Empty password field = keep the current one; "-" clears it.
        if (typeof b.esPass === "string" && b.esPass) patch.esPass = b.esPass === "-" ? "" : b.esPass;
        const cur = getSettings() || {};
        const sb4 = { ...(cur.sb4 || {}) };
        if (typeof b.sb4LeaksUrl === "string") sb4.leaksUrl = b.sb4LeaksUrl.trim();
        if (typeof b.sb4ScanUrl === "string") sb4.scanUrl = b.sb4ScanUrl.trim();
        // Only overwrite the token when a real new one is supplied (not the masked placeholder).
        if (typeof b.sb4Token === "string" && b.sb4Token.trim() && !b.sb4Token.includes("••")) sb4.token = b.sb4Token.trim();
        patch.sb4 = sb4;
        await saveSettings(patch);
        await saveEvent({ ts: Date.now(), type: "admin_settings_changed", ref: null, detail: { leakSource: getSettings().leakSource, tokenChanged: !!b.sb4Token?.trim() }, ip });
        return send(res, 200, { ok: true });
      }
      // --- test the active source for a domain ---
      if (path === "/api/admin/test" && req.method === "POST") {
        let b; try { b = await readBody(req, 2048); } catch { return send(res, 400, { error: "bad" }); }
        const domain = cleanDomain(b.domain) || "example.com";
        try { const r = await leakLookup(domain); return send(res, 200, { ok: true, source: r.source, domain, total: r.total }); }
        catch (e) { return send(res, 200, { ok: false, error: String(e.message || e) }); }
      }
      return send(res, 404, { error: "inconnu" });
    }

    if (req.method === "GET") return serveStatic(req, res);
    return send(res, 405, { error: "method not allowed" });
  } catch (e) {
    console.error("[server]", String(e.message || e));
    return send(res, 500, { error: "erreur interne" });
  }
});

try {
  await connectDb();
} catch (e) {
  console.error("Impossible de se connecter à MongoDB :", e.message);
  process.exit(1);
}
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, async () => { await closeDb(); process.exit(0); });

server.on("error", e => {
  if (e.code === "EADDRINUSE") console.error(`Port ${CFG.port} déjà utilisé. Lancez avec un autre port : PORT=8090 npm start`);
  else if (e.code === "EACCES") console.error(`Permission refusée sur ${CFG.host}:${CFG.port}. Essayez un port > 1024 ou HOST=127.0.0.1.`);
  else console.error("Erreur serveur:", e.message);
  process.exit(1);
});
server.listen(CFG.port, CFG.host, () => {
  console.log(`Kiosk        → http://localhost:${CFG.port}`);
  console.log(`Super-admin  → http://localhost:${CFG.port}/superadmin   (${usingDefaultCreds() ? `identifiants par défaut : ${CFG.adminUser} / ${CFG.adminPass} — À CHANGER` : `utilisateur : ${adminUser()}`})`);
  console.log(`Elasticsearch→ ${CFG.esUrl}/${CFG.esIndex} (server-side only)`);
});
