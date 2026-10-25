// MongoDB data layer for the Forum DSI kiosk.
// Collections:  leads (one doc per visitor, keyed by ref)  ·  events (usage log)
import { MongoClient } from "mongodb";

const URL = process.env.MONGO_URL || "mongodb://localhost:27017";
const DB_NAME = process.env.MONGO_DB || "forum_dsi";

let client = null;
let db = null;

export function getDb() {
  if (!db) throw new Error("DB not connected");
  return db;
}

// Connect with a few retries — in Docker, Mongo may come up a moment after the app.
export async function connectDb({ retries = 10, delayMs = 2000 } = {}) {
  let lastErr;
  for (let i = 1; i <= retries; i++) {
    try {
      client = new MongoClient(URL, { serverSelectionTimeoutMS: 5000, maxPoolSize: 10 });
      await client.connect();
      await client.db(DB_NAME).command({ ping: 1 });
      db = client.db(DB_NAME);
      await ensureIndexes();
      await loadSettings();
      console.log(`MongoDB      → connecté (${DB_NAME})`);
      return db;
    } catch (e) {
      lastErr = e;
      console.warn(`MongoDB indisponible (tentative ${i}/${retries}) : ${e.message}`);
      try { await client?.close(); } catch {}
      if (i < retries) await new Promise(r => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

async function ensureIndexes() {
  await db.collection("leads").createIndex({ ref: 1 }, { unique: true });
  await db.collection("leads").createIndex({ createdAt: -1 });
  await db.collection("events").createIndex({ ts: -1 });
  await db.collection("events").createIndex({ type: 1 });
}

/* ---------- settings (single doc, cached) ---------- */
let settingsCache = null;
const SETTINGS_ID = "config";

export async function loadSettings() {
  settingsCache = (await db.collection("settings").findOne({ _id: SETTINGS_ID })) || {};
  return settingsCache;
}
export function getSettings() { return settingsCache || {}; }
export async function saveSettings(patch) {
  await db.collection("settings").updateOne({ _id: SETTINGS_ID },
    { $set: { ...patch, _updatedAt: new Date() } }, { upsert: true });
  return loadSettings();
}

export async function closeDb() { try { await client?.close(); } catch {} }

/* ---------- writes ---------- */
// Upsert by ref so re-saving the same visitor updates rather than duplicates.
export async function saveLead(lead) {
  const doc = { ...lead, _savedAt: new Date() };
  await db.collection("leads").updateOne({ ref: lead.ref }, { $set: doc }, { upsert: true });
}

export async function saveEvent(ev) {
  await db.collection("events").insertOne({ ...ev, _at: new Date() });
}

/* ---------- reads ---------- */
export async function getRecentLeads(limit = 500) {
  return db.collection("leads").find({}, { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(limit).toArray();
}
export async function getRecentEvents(limit = 800) {
  return db.collection("events").find({}, { projection: { _id: 0 } }).sort({ ts: -1 }).limit(limit).toArray();
}
// For stats we read the full (small) collections. Capped generously as a safety net.
export async function getAllLeads(cap = 100000) {
  return db.collection("leads").find({}, { projection: { _id: 0 } }).limit(cap).toArray();
}
export async function getAllEvents(cap = 200000) {
  return db.collection("events").find({}, { projection: { _id: 0 } }).limit(cap).toArray();
}
