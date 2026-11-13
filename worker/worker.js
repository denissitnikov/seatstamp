// Cloudflare Worker + SQLite Durable Object (`SeatCoordinator`) for Stripe Checkout Session
// verification and Ed25519 seat ticket signing.
//
// Request format (`POST /`):
//   { action: "activate" | "deactivate", key: "<orderKey>", seat: "<16-hex>" [, ticket: "LK1-..."] [, minIssued: <unixSeconds>] }
//   { action: "claim_checkout", handoff: "chk_<32-hex>", seat: "<16-hex>" [, fallbackSearch: true] [, minIssued: <unixSeconds>] }
//   { action: "recover", email: "<purchase email>" }   (needs STRIPE_SECRET_KEY + RESEND_API_KEY + RECEIPT_FROM_EMAIL)
//   { action: "erase", key: "<purchase key>", adminToken: "<ADMIN_TOKEN>" }   (needs ADMIN_TOKEN; wipes `lic:<keyHash>`)
//
// Bindings (`worker/wrangler.jsonc`) & secrets (`wrangler secret put`):
//   - Durable Object `SEAT_DO` -> `SeatCoordinator` (`new_sqlite_classes`, works on Workers Free plan)
//   - Optional rate-limit binding `POST_RATE_LIMITER` (commented example in `worker/wrangler.jsonc`): checked for
//     every `POST /` after the Origin check, keyed by a digest of the client IP; `success: false` answers
//     `429 rate_limited` with `Retry-After: 60`. Approximate and per Cloudflare location. Unset: per-isolate limits only.
//   - Secret `ED25519_PKCS8_B64`: Base64 of the Ed25519 license private key (`swift run license-tool --init-keypair`)
//   - Secret `STRIPE_SECRET_KEY`: Stripe key (`rk_live_...` with Checkout Sessions, PaymentIntents, Charges, and Disputes: Read)
//   - Optional secret `RESEND_API_KEY`: Resend API key (`re_...`) for the one-time `/thank-you` backup email and `action: "recover"` key recovery
//   - Optional var `RECEIPT_FROM_EMAIL`: Sender address for the one-time backup email (e.g. `"MyApp <keys@myapp.com>"`)
//   - Var `TICKET_SCHEME`: Payload scheme in field 0 of signed tickets (default `"SEATSTAMP-V1"`).
//   - Optional var `TICKET_PREFIX`: Outer token prefix (default `"LK1-"`).
//   - Optional var `KEY_HASH_DOMAIN`: Prefix hashed with purchase keys for DO names (default `"seatstamp-key-v1|"`).
//   - Optional var `MAX_SEATS`: Per-license Mac seat cap (default `"2"`).
//   - Optional var `SEAT_RELEASES_PER_YEAR`: Seat releases (deactivations plus evictions) allowed per purchase per
//     rolling 365 days, integer 0 to 64 (default: the resolved `MAX_SEATS`). A release over the cap returns
//     `429 release_limit`.
//   - Optional var `THANK_YOU_WINDOW_SECONDS`: Seconds after payment during which `/thank-you` embeds the key (default `"3600"`).
//   - Optional var `EVICT_OLDEST_SEAT_AFTER_DAYS`: If > 0 (e.g. `"30"`), when all seats are full and the least
//     recently activated seat has been idle for N days, soft-releases that seat so a user who wiped or replaced
//     an old Mac is not locked out. At most one eviction per N days, and only while the release budget has room.
//     Default `"0"` (strict cap).
//   - Optional var `APP_NAME`: Display name on `/thank-you` and `.txt` backups (default `"Your App"`).
//   - Optional var `APP_URL_SCHEME`: URL scheme for `/thank-you` deep link (default `"myapp"` -> `myapp://activate?key=...`).
//   - Optional var `ACTIVATION_PAGE_URL`: https URL of the page that email buttons link to (default: this Worker's
//     `/open`). Webmail strips `myapp://` links, so emails link to `<page>#key=...` and the page opens the app.
//   - Optional var `STRIPE_ALLOWED_PAYMENT_LINKS`: Comma-separated `plink_...` allowlist.
//   - Optional var `ED25519_PUB_B64`: Base64 of the 32-byte Ed25519 public key (otherwise derived from `ED25519_PKCS8_B64`).
//     When both are set they must match; a mismatch makes `deactivate` answer `500 signing_error`.
//   - Optional var `ED25519_RETIRED_PUB_B64`: Comma-separated Base64 32-byte public keys of retired license keys
//     (first 4 used). Only `deactivate` accepts tickets signed by them, so a Mac with an old ticket can release its
//     seat after a key rotation. Signing always uses `ED25519_PKCS8_B64`. Default: no retired key is accepted.
//   - Optional secret `SEAT_PEPPER`: When set, the `seat` column stores the first 16 hex characters of
//     HMAC-SHA256(pepper, seat code) instead of the seat code, so a dump of storage cannot be matched to a Mac.
//     Rows stored before the pepper was set are renamed on their next activate or deactivate. Never change or
//     remove it once set: every active Mac would look like a new Mac. Default: seat codes are stored as sent.
//   - Optional secret `ADMIN_TOKEN`: At least 32 characters. Enables `action: "erase"` (used by
//     `license-tool --erase-key`), which wipes the license record of one purchase key. Unset or shorter: `erase`
//     answers `501 erase_unconfigured`. `license-tool` reads the same value from the environment variable
//     `SEATSTAMP_ADMIN_TOKEN` on the developer's Mac, never from its arguments or a file in the repository.
//   - Optional var `ENVIRONMENT`: `"test"` in the local `node:test` harness to enable `env.__TEST_FETCH`.

import { DurableObject } from "cloudflare:workers";

const DEFAULT_MAX_SEATS = 2;
const DEFAULT_THANK_YOU_WINDOW_SECONDS = 3600;
const DEFAULT_TICKET_SCHEME = "SEATSTAMP-V1";
const DEFAULT_TICKET_PREFIX = "LK1-";
const DEFAULT_KEY_HASH_DOMAIN = "seatstamp-key-v1|";
const DEFAULT_APP_NAME = "Your App";
const DEFAULT_APP_URL_SCHEME = "myapp";

const MAX_BODY_BYTES = 2048;
const MAX_KEY_LENGTH = 256;
const MAX_TICKET_LENGTH = 512;

const REVERIFY_TTL_MS = 60 * 60 * 1000;
const OUTAGE_REMINT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const RELEASE_WINDOW_SEC = 365 * 86_400;
const RELEASE_LOG_MAX = 64;
// Rows of deactivated or evicted Macs are deleted this long after `deactivated_at` (unix seconds).
const DEACTIVATED_SEAT_RETENTION_SEC = 30 * 86_400;
const NEGATIVE_CACHE_TTL_MS = 5 * 60 * 1000;
const NEGATIVE_CACHE_MAX = 512;
const RECENT_VALID_TTL_MS = 45 * 1000;
const RECENT_VALID_MAX = 256;
const CLIENT_RATE_LIMIT_PER_MIN = 12;
const CLAIM_RATE_LIMIT_PER_MIN = 30;
const THANK_YOU_RATE_LIMIT_PER_MIN = 3;
const ERASE_RATE_LIMIT_PER_MIN = 5;
const MIN_ADMIN_TOKEN_LENGTH = 32;
const MAX_ADMIN_TOKEN_LENGTH = 512;
const CLIENT_RATE_MAP_MAX = 1024;
// Stripe call budget. It lives in the memory of one isolate, so it is per isolate, not global: other
// isolates and other Cloudflare locations each have their own budget.
const PER_ISOLATE_STORE_WINDOW_MS = 10 * 1000;
const PER_ISOLATE_STORE_MAX_CALLS = 40;

const STRIPE_API_VERSION = "2026-10-28.endive";
const STRIPE_SESSION_RE = /^cs_(live|test)_[A-Za-z0-9_]{24,140}$/;
const HANDOFF_TOKEN_RE = /^chk_[0-9a-f]{32}$/;
const HANDOFF_TTL_MS = 24 * 60 * 60 * 1000;
const HANDOFF_FALLBACK_SEARCH_COOLDOWN_MS = 15 * 1000;
const HANDOFF_FALLBACK_MAX_PAGES = 2;
const HANDOFF_FALLBACK_MAX_LINKS = 8;
const HANDOFF_SEARCH_MIN_AGE_MS = 30_000;
const HANDOFF_MAX_SEARCHES = 40;

const EMAIL_MAX_ATTEMPTS = 3;
const RECOVER_COOLDOWN_MS = 15 * 60 * 1000;
const RECOVER_RATE_LIMIT_PER_WINDOW = 3;
const RECOVER_RATE_WINDOW_MS = 10 * 60 * 1000;
const RECOVER_MAX_KEYS_PER_EMAIL = 5;

// RFC 8410 ASN.1 PKCS#8 v1 header for a 32-byte Ed25519 seed
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

let cachedSigningKey = null;
let cachedSigningSecret = null;
let cachedVerifyKeys = null;
let cachedVerifySource = null;

function resolveTicketScheme(env) {
  const s = typeof env?.TICKET_SCHEME === "string" ? env.TICKET_SCHEME.trim() : "";
  return s && !s.includes("|") ? s : DEFAULT_TICKET_SCHEME;
}

function resolveTicketPrefix(env) {
  const p = typeof env?.TICKET_PREFIX === "string" ? env.TICKET_PREFIX.trim() : "";
  return p || DEFAULT_TICKET_PREFIX;
}

function resolveKeyHashDomain(env) {
  const d = typeof env?.KEY_HASH_DOMAIN === "string" ? env.KEY_HASH_DOMAIN : "";
  return d || DEFAULT_KEY_HASH_DOMAIN;
}

function resolveMaxSeats(env) {
  const n = Number.parseInt(String(env?.MAX_SEATS ?? ""), 10);
  return Number.isInteger(n) && n >= 1 && n <= 64 ? n : DEFAULT_MAX_SEATS;
}

function resolveSeatReleasesPerYear(env) {
  const n = Number.parseInt(String(env?.SEAT_RELEASES_PER_YEAR ?? ""), 10);
  return Number.isInteger(n) && n >= 0 && n <= 64 ? n : resolveMaxSeats(env);
}

function resolveThankYouWindowSeconds(env) {
  const n = Number.parseInt(String(env?.THANK_YOU_WINDOW_SECONDS ?? ""), 10);
  return Number.isInteger(n) && n >= 60 && n <= 30 * 86_400 ? n : DEFAULT_THANK_YOU_WINDOW_SECONDS;
}

function resolveEvictOldestAfterMs(env) {
  const days = Number.parseFloat(String(env?.EVICT_OLDEST_SEAT_AFTER_DAYS ?? "0"));
  return Number.isFinite(days) && days > 0 ? Math.floor(days * 86_400_000) : 0;
}

function resolveAppName(env) {
  const n = typeof env?.APP_NAME === "string" ? env.APP_NAME.trim() : "";
  return n ? n.slice(0, 64) : DEFAULT_APP_NAME;
}

function resolveAppUrlScheme(env) {
  const s = typeof env?.APP_URL_SCHEME === "string" ? env.APP_URL_SCHEME.trim() : "";
  return /^[a-z][a-z0-9+.-]{0,31}$/i.test(s) ? s.toLowerCase() : DEFAULT_APP_URL_SCHEME;
}

// Email buttons cannot use `myapp://` (Gmail and most webmail drop non-http links), so they point at an https
// page that opens the app. The key goes in the fragment, which browsers never send to the server.
function activationPageLink(env, origin, key) {
  let base = "";
  const configured = typeof env?.ACTIVATION_PAGE_URL === "string" ? env.ACTIVATION_PAGE_URL.trim() : "";
  if (configured) {
    try {
      const u = new URL(configured);
      if (u.protocol === "https:") base = `${u.origin}${u.pathname}`;
    } catch {
      // Fall back to the Worker's own page.
    }
  }
  if (!base) base = `${origin}/open`;
  return `${base}#key=${encodeURIComponent(key)}`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeTag(rawTag) {
  const trimmed = String(rawTag || "").trim().replace(/\|/g, "-");
  return /^ORD-/i.test(trimmed) ? trimmed.slice(4) : trimmed;
}

function resolveFetch(env) {
  if (env && env.ENVIRONMENT === "test" && typeof env.__TEST_FETCH === "function") {
    return env.__TEST_FETCH;
  }
  return fetch;
}

let ephemeralBootSaltHex = null;
function getEphemeralBootSaltHex() {
  if (!ephemeralBootSaltHex) {
    ephemeralBootSaltHex = [...crypto.getRandomValues(new Uint8Array(32))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  return ephemeralBootSaltHex;
}

// Per-isolate in-memory rate-limit and cache maps. Seat caps and email-claim state live in `SeatCoordinator` SQLite storage.
let rateMinuteSlot = 0;
const clientMinuteCounts = new Map();
let globalStoreWindowStart = 0;
let globalStoreWindowCount = 0;
const negativeKeyCache = new Map();
const recentValidSessionCache = new Map();

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

async function sha256Hex(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Compares the SHA-256 digests of two strings over all 32 bytes, so the time taken does not depend on where they differ.
async function digestsEqual(a, b) {
  const da = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(a)));
  const db = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(b)));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= da[i] ^ db[i];
  return diff === 0;
}

export async function deriveOrderTag(rawKey, env) {
  const domain = resolveKeyHashDomain(env);
  const trimmed = String(rawKey || "").trim();
  const keyHash = await sha256Hex(domain + trimmed);
  return "ORD-" + keyHash.slice(0, 16).toUpperCase();
}

// The value stored in the `seat` column. With the optional `SEAT_PEPPER` secret it is the first 16 hex characters of
// HMAC-SHA256(pepper, seat), so the stored value cannot be matched to a Mac without the secret. Without it, the seat
// code is stored as sent. Tickets are always minted for the raw seat code.
async function storedSeatId(seat, env) {
  const pepper = String(env?.SEAT_PEPPER || "").trim();
  if (!pepper) return seat;
  const hmacKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(seat)));
  return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

async function deriveHandoffDoName(handoffToken, keyHashDomain) {
  const hHash = await sha256Hex(keyHashDomain + "handoff|" + handoffToken);
  return "handoff:" + hHash;
}

function setBoundedCache(map, key, value, maxEntries) {
  const now = Date.now();
  if (map.size >= maxEntries) {
    for (const [k, entry] of map) {
      const exp = typeof entry === "number" ? entry : entry.expiresAt;
      if (exp <= now || map.size >= maxEntries) {
        map.delete(k);
      }
      if (map.size < maxEntries) break;
    }
  }
  map.set(key, value);
}

function isNegativeCached(keyHash) {
  const exp = negativeKeyCache.get(keyHash);
  if (!exp) return false;
  if (exp <= Date.now()) {
    negativeKeyCache.delete(keyHash);
    return false;
  }
  return true;
}

function rememberNegativeKey(keyHash) {
  recentValidSessionCache.delete(keyHash);
  setBoundedCache(negativeKeyCache, keyHash, Date.now() + NEGATIVE_CACHE_TTL_MS, NEGATIVE_CACHE_MAX);
}

function getRecentValidCached(keyHash) {
  const entry = recentValidSessionCache.get(keyHash);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    recentValidSessionCache.delete(keyHash);
    return null;
  }
  return entry;
}

function rememberRecentValidKey(keyHash, createdSec = 0, clientReferenceId = "") {
  negativeKeyCache.delete(keyHash);
  setBoundedCache(
    recentValidSessionCache,
    keyHash,
    { expiresAt: Date.now() + RECENT_VALID_TTL_MS, createdSec, clientReferenceId },
    RECENT_VALID_MAX
  );
}

// Per-minute IP rate limit hashed with the isolate's random boot salt. Separate `scope` values
// keep `/thank-you` and `POST /` counters independent.
async function allowClientAttempt(request, scope, limit) {
  const nowMinute = Math.floor(Date.now() / 60_000);
  if (nowMinute !== rateMinuteSlot) {
    rateMinuteSlot = nowMinute;
    clientMinuteCounts.clear();
  }
  const ip = request.headers.get("CF-Connecting-IP") || "anon";
  const bucket = (await sha256Hex(`${getEphemeralBootSaltHex()}:${nowMinute}:${scope}:${ip}`)).slice(0, 24);
  const current = clientMinuteCounts.get(bucket) || 0;
  if (current >= limit) {
    return false;
  }
  if (!clientMinuteCounts.has(bucket) && clientMinuteCounts.size >= CLIENT_RATE_MAP_MAX) {
    const oldestKey = clientMinuteCounts.keys().next().value;
    if (oldestKey !== undefined) clientMinuteCounts.delete(oldestKey);
  }
  clientMinuteCounts.set(bucket, current + 1);
  return true;
}

function allowClientStoreAttempt(request) {
  return allowClientAttempt(request, "activate", CLIENT_RATE_LIMIT_PER_MIN);
}

function allowThankYouAttempt(request) {
  return allowClientAttempt(request, "thank-you", THANK_YOU_RATE_LIMIT_PER_MIN);
}

// Background `claim_checkout` polling (3s cadence) gets its own budget so it never starves a real activation.
function allowClaimAttempt(request) {
  return allowClientAttempt(request, "claim", CLAIM_RATE_LIMIT_PER_MIN);
}

// Email recovery: 3 requests per 10-minute window per salted IP hash, independent of the per-minute scopes.
const recoverWindowCounts = new Map();
async function allowRecoverAttempt(request) {
  const now = Date.now();
  const windowSlot = Math.floor(now / RECOVER_RATE_WINDOW_MS);
  const ip = request.headers.get("CF-Connecting-IP") || "anon";
  const bucket = (await sha256Hex(`${getEphemeralBootSaltHex()}:${windowSlot}:recover:${ip}`)).slice(0, 24);
  const entry = recoverWindowCounts.get(bucket);
  if (entry && entry.slot === windowSlot && entry.count >= RECOVER_RATE_LIMIT_PER_WINDOW) {
    return false;
  }
  if (!entry || entry.slot !== windowSlot) {
    if (recoverWindowCounts.size >= CLIENT_RATE_MAP_MAX) {
      for (const [k, v] of recoverWindowCounts) {
        if (v.slot !== windowSlot) recoverWindowCounts.delete(k);
        if (recoverWindowCounts.size < CLIENT_RATE_MAP_MAX) break;
      }
      if (recoverWindowCounts.size >= CLIENT_RATE_MAP_MAX) {
        const oldest = recoverWindowCounts.keys().next().value;
        if (oldest !== undefined) recoverWindowCounts.delete(oldest);
      }
    }
    recoverWindowCounts.set(bucket, { slot: windowSlot, count: 1 });
  } else {
    entry.count += 1;
  }
  return true;
}

// Strict shape check for a recovery email. Rejects whitespace, control characters, and anything that is not
// `local@domain.tld`. Does not try to be RFC 5322 complete; Stripe is the source of truth for what matched.
function normalizeRecoveryEmail(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (trimmed.length < 3 || trimmed.length > 254) return null;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return null;
  }
  const at = trimmed.indexOf("@");
  if (at <= 0 || at !== trimmed.lastIndexOf("@")) return null;
  const domain = trimmed.slice(at + 1);
  const dot = domain.indexOf(".");
  if (dot <= 0 || dot === domain.length - 1) return null;
  return { trimmed, lower: trimmed.toLowerCase() };
}

// Secret-keyed digests of the recovery email: without `STRIPE_SECRET_KEY` the hash cannot be tested offline,
// so the `recover:<hmac>` DO name reveals nothing even if storage is dumped. The DO name (the cooldown) uses
// the trimmed address as typed, so another spelling gets its own cooldown. `emailHmac` feeds the provider's
// `Idempotency-Key` and uses the lower-cased address, so at most one email per address per window is sent.
async function deriveRecoverDoName(typedEmail, lowerEmail, keyHashDomain, env) {
  const keyBytes = new TextEncoder().encode(String(env.STRIPE_SECRET_KEY || "").trim());
  const hmacKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hmacHex = async (value) => {
    const mac = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(keyHashDomain + "recover|" + value));
    return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };
  return { doName: "recover:" + (await hmacHex(typedEmail)), emailHmac: await hmacHex(lowerEmail) };
}

function consumeGlobalStoreSlot() {
  const now = Date.now();
  if (now - globalStoreWindowStart >= PER_ISOLATE_STORE_WINDOW_MS) {
    globalStoreWindowStart = now;
    globalStoreWindowCount = 0;
  }
  if (globalStoreWindowCount >= PER_ISOLATE_STORE_MAX_CALLS) {
    return false;
  }
  globalStoreWindowCount += 1;
  return true;
}

// Test-only: clears per-isolate rate-limit and cache maps so each `node:test` case starts from a cold isolate.
// Gated on `ENVIRONMENT === "test"` like `__TEST_FETCH`; a no-op in production.
export function __resetIsolateStateForTests(env) {
  if (!env || env.ENVIRONMENT !== "test") return;
  rateMinuteSlot = 0;
  clientMinuteCounts.clear();
  recoverWindowCounts.clear();
  globalStoreWindowStart = 0;
  globalStoreWindowCount = 0;
  negativeKeyCache.clear();
  recentValidSessionCache.clear();
}

// Test-only: uses up the Stripe call budget of this isolate. Gated on `ENVIRONMENT === "test"`.
export function __exhaustStoreBudgetForTests(env) {
  if (!env || env.ENVIRONMENT !== "test") return;
  globalStoreWindowStart = Date.now();
  globalStoreWindowCount = PER_ISOLATE_STORE_MAX_CALLS;
}

function isLiveStripeSecret(secret) {
  const trimmed = (secret || "").trim();
  return trimmed.startsWith("sk_live_") || trimmed.startsWith("rk_live_");
}

export function classifyKeyFormat(rawKey, env) {
  if (!rawKey || typeof rawKey !== "string") return "invalid";
  const key = rawKey.trim();
  if (key.length < 16 || key.length > MAX_KEY_LENGTH) return "invalid";

  const prefix = resolveTicketPrefix(env);
  if (key.toUpperCase().startsWith(prefix.toUpperCase())) return "invalid";

  if (key.startsWith("cs_")) {
    if (!env?.STRIPE_SECRET_KEY || !STRIPE_SESSION_RE.test(key)) return "invalid";
    if (isLiveStripeSecret(env.STRIPE_SECRET_KEY) && !key.startsWith("cs_live_")) return "invalid";
    return "stripe";
  }

  return "invalid";
}

function securityHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    ...extra,
  };
}

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return Response.json(payload, {
    status,
    headers: securityHeaders(extraHeaders),
  });
}

function toPkcs8Bytes(secretB64) {
  const rawBytes = Uint8Array.from(atob(secretB64.trim()), (c) => c.charCodeAt(0));
  if (rawBytes.length === 32) {
    const pkcs8Bytes = new Uint8Array(48);
    pkcs8Bytes.set(ED25519_PKCS8_PREFIX, 0);
    pkcs8Bytes.set(rawBytes, 16);
    return pkcs8Bytes;
  }
  if (rawBytes.length === 48) {
    for (let i = 0; i < ED25519_PKCS8_PREFIX.length; i++) {
      if (rawBytes[i] !== ED25519_PKCS8_PREFIX[i]) {
        throw new Error("ED25519_PKCS8_B64 48-byte key does not have RFC 8410 Ed25519 PKCS#8 header");
      }
    }
    return rawBytes;
  }
  throw new Error("ED25519_PKCS8_B64 must decode to 32-byte seed or 48-byte PKCS#8 DER");
}

async function getSigningKey(secretB64) {
  if (!secretB64 || typeof secretB64 !== "string") {
    throw new Error("Missing ED25519_PKCS8_B64 secret");
  }
  const trimmed = secretB64.trim();
  if (cachedSigningKey && cachedSigningSecret === trimmed) {
    return cachedSigningKey;
  }
  const pkcs8Bytes = toPkcs8Bytes(trimmed);
  const imported = await crypto.subtle.importKey("pkcs8", pkcs8Bytes, { name: "Ed25519" }, false, ["sign"]);
  cachedSigningKey = imported;
  cachedSigningSecret = trimmed;
  return imported;
}

const MAX_RETIRED_VERIFY_KEYS = 4;

function decodeRawPublicKey(b64, name) {
  const raw = Uint8Array.from(atob(String(b64).trim()), (c) => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error(`${name} must decode to a 32-byte raw public key`);
  return raw;
}

// Returns the current verify key followed by the retired ones (`ED25519_RETIRED_PUB_B64`, first 4 entries).
// Throws when a key cannot be loaded, including an `ED25519_PUB_B64` override that is not the public key of
// `ED25519_PKCS8_B64` (a stale override after a rotation).
async function getVerifyKeys(env) {
  const pubOverride = (env.ED25519_PUB_B64 || "").trim();
  const pkcs8Secret = typeof env.ED25519_PKCS8_B64 === "string" ? env.ED25519_PKCS8_B64.trim() : "";
  const retiredList = String(env.ED25519_RETIRED_PUB_B64 || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, MAX_RETIRED_VERIFY_KEYS);
  const source = JSON.stringify([pubOverride, pkcs8Secret, retiredList]);
  if (cachedVerifyKeys && cachedVerifySource === source) {
    return cachedVerifyKeys;
  }

  let derivedRaw = null;
  if (pkcs8Secret) {
    const extractable = await crypto.subtle.importKey("pkcs8", toPkcs8Bytes(pkcs8Secret), { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", extractable);
    derivedRaw = fromBase64Url(jwk.x);
  }
  let currentRaw;
  if (pubOverride) {
    currentRaw = decodeRawPublicKey(pubOverride, "ED25519_PUB_B64");
    if (derivedRaw && !currentRaw.every((b, i) => b === derivedRaw[i])) {
      throw new Error("ED25519_PUB_B64 is not the public key of ED25519_PKCS8_B64");
    }
  } else {
    if (!derivedRaw) throw new Error("Missing ED25519_PKCS8_B64 secret");
    currentRaw = derivedRaw;
  }

  const keys = [await crypto.subtle.importKey("raw", currentRaw, { name: "Ed25519" }, false, ["verify"])];
  for (const entry of retiredList) {
    const raw = decodeRawPublicKey(entry, "ED25519_RETIRED_PUB_B64");
    keys.push(await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]));
  }
  cachedVerifyKeys = keys;
  cachedVerifySource = source;
  return keys;
}

/**
 * Verifies a `<prefix><base64url(payload)>.<base64url(sig)>` seat ticket minted by this Worker.
 * Canonical payload: `<scheme>|ORD-<tag>|<issuedUnixSeconds>|<seat16hex>`.
 */
export async function verifySeatTicket(ticket, expectedSeat, env) {
  try {
    if (typeof ticket !== "string" || ticket.length > MAX_TICKET_LENGTH) return { ok: false };
    const prefix = resolveTicketPrefix(env);
    const scheme = resolveTicketScheme(env);
    const trimmed = ticket.trim();
    if (!trimmed.startsWith(prefix)) return { ok: false };

    const rest = trimmed.slice(prefix.length);
    const m = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(rest);
    if (!m) return { ok: false };
    const payloadBytes = fromBase64Url(m[1]);
    const sigBytes = fromBase64Url(m[2]);
    if (sigBytes.length !== 64 || payloadBytes.length === 0 || payloadBytes.length > 256) return { ok: false };

    const verifyKeys = await getVerifyKeys(env);
    let sigOk = false;
    for (const verifyKey of verifyKeys) {
      if (await crypto.subtle.verify("Ed25519", verifyKey, sigBytes, payloadBytes)) {
        sigOk = true;
        break;
      }
    }
    if (!sigOk) return { ok: false };

    const payloadStr = new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes);
    const parts = payloadStr.split("|");
    if (parts.length !== 4 || parts[0] !== scheme) return { ok: false };
    if (!parts[1].startsWith("ORD-") || parts[1].length <= 4) return { ok: false };
    if (!/^\d{1,12}$/.test(parts[2])) return { ok: false };
    if (!/^[0-9a-f]{16}$/.test(parts[3]) || parts[3] !== expectedSeat) return { ok: false };

    return { ok: true, tag: parts[1].slice(4), issued: Number(parts[2]), seat: parts[3] };
  } catch {
    return { ok: false };
  }
}

// Headers for every request to api.stripe.com. The pinned `Stripe-Version` keeps responses stable when the
// account's default API version changes.
function stripeHeaders(secret) {
  return { Authorization: `Bearer ${String(secret || "").trim()}`, "Stripe-Version": STRIPE_API_VERSION };
}

// Pure validation of an expanded Stripe Checkout Session object, shared by single-session verification
// and by email recovery. Returns `true` (paid and unrefunded), `false` (invalid), `"pending"` (open, or
// complete but unpaid, and not reversed), `"disputed"` (paid and unrefunded, but the charge is marked
// disputed, so the caller must resolve the disputes), or `null` (needs PaymentIntents/Charges expansion
// that was not present, so the caller must fail closed).
function evaluateStripeSession(session, env) {
  if (!session || session.object !== "checkout.session") return false;
  if (isLiveStripeSecret(env.STRIPE_SECRET_KEY) && session.livemode !== true) return false;
  if (session.mode && session.mode !== "payment") return false;

  if (env.STRIPE_ALLOWED_PAYMENT_LINKS) {
    const allowedLinks = String(env.STRIPE_ALLOWED_PAYMENT_LINKS)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (allowedLinks.length > 0 && (!session.payment_link || !allowedLinks.includes(String(session.payment_link)))) {
      return false;
    }
  }

  const isPaidOrFreePromo =
    session.status === "complete" &&
    (session.payment_status === "paid" || session.payment_status === "no_payment_required");
  if (!isPaidOrFreePromo) {
    const awaitingPayment =
      session.status === "open" || (session.status === "complete" && session.payment_status === "unpaid");
    const charge = session.payment_intent?.latest_charge;
    const chargeReversed =
      Boolean(charge) && typeof charge === "object" && (charge.refunded === true || charge.disputed === true);
    return awaitingPayment && !chargeReversed ? "pending" : false;
  }

  // Stripe keeps `session.payment_status === "paid"` after a refund or dispute, so inspect `latest_charge`.
  const requiresExpandedChargeCheck =
    session.payment_status === "paid" &&
    (typeof session.amount_total !== "number" || session.amount_total > 0);
  if (!requiresExpandedChargeCheck) return true;

  if (!session.payment_intent || typeof session.payment_intent !== "object") return null;
  const pi = session.payment_intent;
  if (pi.status && pi.status !== "succeeded") return false;
  if (typeof pi.amount === "number" && pi.amount > 0 && pi.amount_received === 0) return false;
  if (!pi.latest_charge || typeof pi.latest_charge !== "object") return null;
  const ch = pi.latest_charge;
  if (ch.refunded === true) return false;
  if (typeof ch.amount === "number" && ch.amount > 0 && (ch.amount_refunded || 0) >= ch.amount) return false;
  if (ch.disputed === true) return "disputed";
  return true;
}

// Resolves a charge marked `disputed` by listing the PaymentIntent's disputes. Returns `true` (every dispute
// was won or closed as a warning), `false` (a dispute was lost or prevented), `"payment_disputed"` (a dispute
// is still open, or has an unknown status), `"rate_limited"`, or `null` (missing id, upstream error, an
// empty or truncated list).
async function resolveStripeDisputes(paymentIntentId, env) {
  if (typeof paymentIntentId !== "string" || !/^pi_[A-Za-z0-9_]+$/.test(paymentIntentId)) return null;
  if (!consumeGlobalStoreSlot()) return "rate_limited";
  let resp;
  try {
    resp = await resolveFetch(env)(
      `https://api.stripe.com/v1/disputes?payment_intent=${encodeURIComponent(paymentIntentId)}&limit=100`,
      {
        method: "GET",
        headers: stripeHeaders(env.STRIPE_SECRET_KEY),
        signal: AbortSignal.timeout(5000),
      }
    );
  } catch {
    return null;
  }
  if (resp.status !== 200) return null;
  let payload;
  try {
    payload = await resp.json();
  } catch {
    return null;
  }
  if (!payload || !Array.isArray(payload.data) || payload.data.length === 0 || payload.has_more === true) return null;
  const statuses = payload.data.map((d) => d?.status);
  if (statuses.some((st) => st === "lost" || st === "prevented")) return false;
  if (statuses.every((st) => st === "won" || st === "warning_closed")) return true;
  return "payment_disputed";
}

// Verifies a purchase key against Stripe.
// Returns `true` (valid), `false` (invalid/refunded/lost dispute), `"pending"` (payment not settled yet; never cached),
// `"payment_disputed"` (a dispute is still open; never cached),
// `"rate_limited"`, or `null` (upstream error).
// When `outMeta` is passed, populates `outMeta.createdSec`, `outMeta.customerEmail`, and `outMeta.clientReferenceId` in memory.
async function verifyKeyWithStore(key, keyHash, env, { bypassRecentValidCache = false, outMeta = null } = {}) {
  const kind = classifyKeyFormat(key, env);
  if (kind === "invalid") return false;

  if (keyHash && isNegativeCached(keyHash)) {
    return false;
  }
  if (keyHash && !bypassRecentValidCache) {
    const cached = getRecentValidCached(keyHash);
    if (cached) {
      if (outMeta && typeof outMeta === "object") {
        outMeta.createdSec = cached.createdSec || 0;
        outMeta.clientReferenceId = cached.clientReferenceId || "";
      }
      return true;
    }
  }
  if (!consumeGlobalStoreSlot()) {
    return "rate_limited";
  }

  // Path 1: Direct Stripe Checkout Session (`cs_live_...` or `cs_test_...`)
  if (kind === "stripe" && env.STRIPE_SECRET_KEY) {
    const secret = env.STRIPE_SECRET_KEY.trim();
    const isLiveSecret = isLiveStripeSecret(secret);
    if (isLiveSecret && !key.startsWith("cs_live_")) {
      if (keyHash) rememberNegativeKey(keyHash);
      return false;
    }

    const baseUrl = `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(key)}`;
    const fetchImpl = resolveFetch(env);
    let resp;
    try {
      resp = await fetchImpl(`${baseUrl}?expand[]=payment_intent.latest_charge`, {
        method: "GET",
        headers: stripeHeaders(secret),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      return null;
    }

    // Only a 404 is a definite "no such session". Every other non-2xx status (401, 403, 429, 5xx, or an
    // unexpected 4xx such as 400 after an API change) returns null: 502 for new seats, keep existing seats,
    // never wipe. A 403 here usually means the restricted Stripe key is missing a read permission.
    if (resp.status === 404) {
      if (keyHash) rememberNegativeKey(keyHash);
      return false;
    }
    if (!resp.ok) {
      return null;
    }

    let session;
    try {
      session = await resp.json();
    } catch {
      return null;
    }

    const verdict = evaluateStripeSession(session, env);
    let finalVerdict = verdict;
    if (verdict === "disputed") finalVerdict = await resolveStripeDisputes(session.payment_intent && session.payment_intent.id, env);
    if (finalVerdict !== true) {
      if (finalVerdict === false && keyHash) rememberNegativeKey(keyHash);
      return finalVerdict;
    }

    const createdSec =
      Number(session.payment_intent?.latest_charge?.created) ||
      Number(session.payment_intent?.created) ||
      Number(session.created) ||
      0;
    const customerEmail =
      typeof session.customer_details?.email === "string"
        ? session.customer_details.email.trim()
        : "";
    const clientReferenceId =
      typeof session.client_reference_id === "string"
        ? session.client_reference_id.trim()
        : "";
    if (outMeta && typeof outMeta === "object") {
      outMeta.createdSec = createdSec;
      outMeta.customerEmail = customerEmail;
      outMeta.clientReferenceId = clientReferenceId;
    }

    if (keyHash) rememberRecentValidKey(keyHash, createdSec, clientReferenceId);
    return true;
  }

  return false;
}

// Closed-tab fallback: lists recent completed Stripe Checkout Sessions and finds one whose
// `client_reference_id` matches `handoffToken`, then runs full `verifyKeyWithStore` (including
// `livemode`, `STRIPE_ALLOWED_PAYMENT_LINKS`, and expanded `payment_intent.latest_charge` refund checks).
//
// Stripe's list endpoint has no `client_reference_id` filter, so narrow the window server-side instead:
// `status=complete` drops abandoned page opens, `created[gte]` bounds it to the handoff TTL, and each list
// is pinned to one `payment_link` when 1 to `HANDOFF_FALLBACK_MAX_LINKS` links are allowlisted (one list per
// link). Up to 2 pages of 100 are scanned per link.
function buildStripeSessionListURL(env, nowMs, startingAfter = "", paymentLink = "") {
  const params = new URLSearchParams();
  params.set("status", "complete");
  params.set("limit", "100");
  params.set("created[gte]", String(Math.floor((nowMs - HANDOFF_TTL_MS) / 1000)));
  if (paymentLink) {
    params.set("payment_link", paymentLink);
  }
  if (startingAfter) {
    params.set("starting_after", startingAfter);
  }
  return `https://api.stripe.com/v1/checkout/sessions?${params.toString()}`;
}

async function findStripeSessionByHandoff(handoffToken, keyHashDomain, env) {
  if (!env.STRIPE_SECRET_KEY) return "";
  if (!consumeGlobalStoreSlot()) return "rate_limited";

  const secret = env.STRIPE_SECRET_KEY.trim();
  const fetchImpl = resolveFetch(env);
  const nowMs = Date.now();
  const allowedLinks = String(env.STRIPE_ALLOWED_PAYMENT_LINKS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  // No allowlist, or more links than one search may list: one unfiltered list over the whole account.
  const linkFilters =
    allowedLinks.length >= 1 && allowedLinks.length <= HANDOFF_FALLBACK_MAX_LINKS ? allowedLinks : [""];

  for (const paymentLink of linkFilters) {
    let startingAfter = "";
    for (let page = 0; page < HANDOFF_FALLBACK_MAX_PAGES; page++) {
      let resp;
      try {
        resp = await fetchImpl(buildStripeSessionListURL(env, nowMs, startingAfter, paymentLink), {
          method: "GET",
          headers: stripeHeaders(secret),
          signal: AbortSignal.timeout(5000),
        });
      } catch {
        return null;
      }

      if (!resp.ok) {
        return null;
      }

      let payload;
      try {
        payload = await resp.json();
      } catch {
        return null;
      }
      const items = Array.isArray(payload?.data) ? payload.data : [];
      for (const item of items) {
        if (
          !item ||
          item.object !== "checkout.session" ||
          item.client_reference_id !== handoffToken ||
          item.status !== "complete" ||
          typeof item.id !== "string" ||
          !STRIPE_SESSION_RE.test(item.id)
        ) {
          continue;
        }
        const candidateKeyHash = await sha256Hex(keyHashDomain + item.id);
        const verified = await verifyKeyWithStore(item.id, candidateKeyHash, env);
        if (verified === true) {
          return item.id;
        }
        if (verified === "rate_limited") {
          return "rate_limited";
        }
        if (verified === null) {
          return null;
        }
        if (verified === "payment_disputed") {
          continue;
        }
      }

      const lastId = items.length > 0 ? items[items.length - 1]?.id : "";
      if (payload?.has_more !== true || typeof lastId !== "string" || !lastId) {
        break;
      }
      startingAfter = lastId;
    }
  }
  return "";
}

function renderLicenseEmailHtml({ appName, linkFor, maxSeats, keys, heading, intro, footer }) {
  const safeAppName = escapeHtml(appName);
  const keyBlocks = keys
    .map((id) => {
      const safeId = escapeHtml(id);
      const safeDeepLink = escapeHtml(linkFor(id));
      return (
        `<div style="margin:16px 0;padding:16px;background:#f5f5f7;border:1px solid #e5e5ea;border-radius:10px;">` +
        `<div style="font-size:12px;font-weight:600;color:#6e6e73;margin-bottom:6px;">License Key</div>` +
        `<div style="font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12.5px;` +
        `line-height:1.45;word-break:break-all;background:#ffffff;border:1px solid #d1d1d6;border-radius:7px;` +
        `padding:10px 12px;color:#1d1d1f;user-select:all;">${safeId}</div>` +
        `<div style="margin-top:12px;">` +
        `<a href="${safeDeepLink}" style="display:inline-block;padding:10px 16px;background:#0a84ff;color:#ffffff;` +
        `text-decoration:none;font-size:13.5px;font-weight:600;border-radius:8px;">Open in ${safeAppName}</a>` +
        `</div>` +
        `</div>`
      );
    })
    .join("");

  return (
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>` +
    `<body style="margin:0;padding:24px 12px;background:#f5f5f7;color:#1d1d1f;` +
    `font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',Roboto,Helvetica,Arial,sans-serif;">` +
    `<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;margin:0 auto;` +
    `background:#ffffff;border:1px solid #e5e5ea;border-radius:14px;">` +
    `<tr><td style="padding:28px 26px;">` +
    `<div style="font-size:18px;font-weight:700;letter-spacing:-0.01em;margin:0 0 8px;color:#1d1d1f;">${escapeHtml(heading)}</div>` +
    `<p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#424245;">${escapeHtml(intro)}</p>` +
    `${keyBlocks}` +
    `<p style="margin:16px 0 6px;font-size:12.5px;line-height:1.5;color:#6e6e73;">` +
    `If the button does not open ${safeAppName}, copy the license key above and paste it in ` +
    `<b>${safeAppName} &rsaquo; Settings &rsaquo; Enter License Key</b>.` +
    `</p>` +
    `<p style="margin:8px 0 0;font-size:12.5px;line-height:1.5;color:#6e6e73;">` +
    `Valid on up to ${Number(maxSeats)} Macs. ${escapeHtml(footer)}` +
    `</p>` +
    `</td></tr></table></body></html>`
  );
}

// Returns true only when the email provider answers with a 2xx status; false for any other status, a thrown
// fetch, a timeout, or missing configuration. Every attempt for one key carries the same `Idempotency-Key`.
async function sendBackupEmail(recipientEmail, sessionId, keyHash, env, origin) {
  if (!recipientEmail || !env.RESEND_API_KEY || !env.RECEIPT_FROM_EMAIL) return false;
  const appName = resolveAppName(env);
  const maxSeats = resolveMaxSeats(env);
  const linkFor = (id) => activationPageLink(env, origin, id);
  const deepLink = linkFor(sessionId);
  const text =
    `Thank you for buying ${appName}.\n\n` +
    `Your license key (valid on up to ${maxSeats} Macs):\n${sessionId}\n\n` +
    `One-click activation link on macOS:\n${deepLink}\n\n` +
    `Keep this email for your records in case you move to a new Mac or reinstall macOS.\n`;
  const html = renderLicenseEmailHtml({
    appName,
    linkFor,
    maxSeats,
    keys: [sessionId],
    heading: `Thank you for supporting ${appName}`,
    intro: "Here is your lifetime license key. Click below on your Mac to activate it, or paste the key into Settings.",
    footer: "Keep this email for your records when moving to a new Mac or reinstalling macOS.",
  });

  try {
    const resp = await resolveFetch(env)("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY.trim()}`,
        "Content-Type": "application/json",
        "Idempotency-Key": `thank-you-receipt-${keyHash}`,
      },
      body: JSON.stringify({
        from: env.RECEIPT_FROM_EMAIL.trim(),
        to: [recipientEmail],
        subject: `Your ${appName} License Key`,
        text,
        html,
      }),
      signal: AbortSignal.timeout(5000),
    });
    return resp.status >= 200 && resp.status < 300;
  } catch {
    // A failed send never fails the /thank-you page response; the caller releases the claim instead.
    return false;
  }
}

// Lists completed Checkout Sessions for one exact `customer_details[email]` value with charges expanded,
// and returns the ids that pass `evaluateStripeSession`. Stripe's filter is case-sensitive.
// `failure` is null, "rate_limited" (no free budget slot; checked only when `slotTaken` is false), or
// "upstream" (thrown fetch, unparsable JSON, or any status other than 200 and 400). A 400 is an empty result.
// One page of up to 100 sessions, no pagination; the result is capped at `RECOVER_MAX_KEYS_PER_EMAIL`.
async function listValidSessionIdsForEmail(emailVariant, env, { slotTaken = false } = {}) {
  if (!slotTaken && !consumeGlobalStoreSlot()) return { ids: [], recipient: "", failure: "rate_limited" };
  const params = new URLSearchParams();
  params.set("customer_details[email]", emailVariant);
  params.set("status", "complete");
  params.set("limit", "100");
  const allowedLinks = String(env.STRIPE_ALLOWED_PAYMENT_LINKS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowedLinks.length === 1) {
    params.set("payment_link", allowedLinks[0]);
  }
  params.append("expand[]", "data.payment_intent.latest_charge");
  let resp;
  try {
    resp = await resolveFetch(env)(`https://api.stripe.com/v1/checkout/sessions?${params.toString()}`, {
      method: "GET",
      headers: stripeHeaders(env.STRIPE_SECRET_KEY),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return { ids: [], recipient: "", failure: "upstream" };
  }
  if (resp.status === 400) return { ids: [], recipient: "", failure: null };
  if (resp.status !== 200) return { ids: [], recipient: "", failure: "upstream" };
  let payload;
  try {
    payload = await resp.json();
  } catch {
    return { ids: [], recipient: "", failure: "upstream" };
  }
  const ids = [];
  let recipient = "";
  for (const session of Array.isArray(payload?.data) ? payload.data : []) {
    if (ids.length >= RECOVER_MAX_KEYS_PER_EMAIL) break;
    if (typeof session?.id !== "string" || !STRIPE_SESSION_RE.test(session.id) || ids.includes(session.id)) continue;
    let verdict = evaluateStripeSession(session, env);
    if (verdict === "disputed") verdict = await resolveStripeDisputes(session.payment_intent && session.payment_intent.id, env);
    if (verdict !== true) continue;
    ids.push(session.id);
    if (!recipient && typeof session.customer_details?.email === "string") {
      recipient = session.customer_details.email.trim();
    }
  }
  return { ids, recipient, failure: null };
}

// Off-path recovery job: look up the buyer's paid sessions and send one consolidated email. Runs inside
// `ctx.waitUntil` so the HTTP response timing never depends on whether the email exists. Nothing here is
// persisted or logged; the email string lives only in this closure. The caller already took the budget slot
// for the first list call. `releaseCooldown` frees the cooldown after a failed lookup that found nothing or a
// failed send; a clean lookup with zero matches keeps it.
async function runEmailRecovery({ trimmedEmail, lowerEmail, emailHmac, nowMs, origin }, env, releaseCooldown = async () => {}) {
  const release = async () => {
    try {
      await releaseCooldown();
    } catch {
      // The 15-minute alarm still clears the cooldown.
    }
  };
  let { ids, recipient, failure } = await listValidSessionIdsForEmail(lowerEmail, env, { slotTaken: true });
  let anyFailure = Boolean(failure);
  if (ids.length === 0) {
    // Stripe matches case-sensitively. Try the exact typed casing, or a capitalized first letter for
    // iOS auto-capitalized checkouts, but only one extra call.
    const fallback = trimmedEmail !== lowerEmail ? trimmedEmail : lowerEmail[0].toUpperCase() + lowerEmail.slice(1);
    if (fallback !== lowerEmail) {
      ({ ids, recipient, failure } = await listValidSessionIdsForEmail(fallback, env));
      if (failure) anyFailure = true;
    }
  }
  if (ids.length === 0 || !recipient) {
    if (anyFailure) await release();
    return;
  }

  const appName = resolveAppName(env);
  const maxSeats = resolveMaxSeats(env);
  const linkFor = (id) => activationPageLink(env, origin, id);
  const keyLines = ids
    .map((id) => `License key: ${id}\nOne-click activation: ${linkFor(id)}\n`)
    .join("\n");
  const text =
    `Here ${ids.length === 1 ? "is the license key" : "are the license keys"} for ${appName} linked to this email address.\n\n` +
    `${keyLines}\n` +
    `Each key works on up to ${maxSeats} Macs. If you did not request this, you can ignore this message.\n`;
  const html = renderLicenseEmailHtml({
    appName,
    linkFor,
    maxSeats,
    keys: ids,
    heading: `Your ${appName} ${ids.length === 1 ? "License Key" : "License Keys"}`,
    intro:
      ids.length === 1
        ? `Here is the ${appName} license key linked to this email address.`
        : `Here are the ${ids.length} ${appName} license keys linked to this email address.`,
    footer: "If you did not request this email, you can ignore it.",
  });
  let sent = false;
  try {
    const resp = await resolveFetch(env)("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY.trim()}`,
        "Content-Type": "application/json",
        "Idempotency-Key": `recover-${emailHmac}-${Math.floor(nowMs / RECOVER_COOLDOWN_MS)}`,
      },
      body: JSON.stringify({
        from: env.RECEIPT_FROM_EMAIL.trim(),
        to: [recipient],
        subject: `Your ${appName} License Key`,
        text,
        html,
      }),
      signal: AbortSignal.timeout(5000),
    });
    sent = resp.status >= 200 && resp.status < 300;
  } catch {
    sent = false;
  }
  if (!sent) await release();
}

const MAX_CLIENT_MIN_ISSUED_AHEAD_SEC = 366 * 86_400;

async function mintSeatTicket(tag, seat, env, revokedBeforeFloor = 0, clientMinIssued = 0) {
  const signingKey = await getSigningKey(env.ED25519_PKCS8_B64);
  const scheme = resolveTicketScheme(env);
  const prefix = resolveTicketPrefix(env);
  const cleanTag = normalizeTag(tag);
  const nowSec = Math.floor(Date.now() / 1000);
  const issued = Math.max(
    nowSec,
    (Number(revokedBeforeFloor) || 0) + 1,
    Math.min(Number(clientMinIssued) || 0, nowSec + MAX_CLIENT_MIN_ISSUED_AHEAD_SEC)
  );
  const payloadStr = `${scheme}|ORD-${cleanTag}|${issued}|${seat}`;
  const payloadBytes = new TextEncoder().encode(payloadStr);
  const sigBytes = new Uint8Array(await crypto.subtle.sign("Ed25519", signingKey, payloadBytes));
  return `${prefix}${toBase64Url(payloadBytes)}.${toBase64Url(sigBytes)}`;
}

// Serializes seat updates per key (`lic:<keyHash>`) and delays table creation until store
// verification succeeds so invalid keys leave no storage behind.
//
// Schema (v2):
//   meta  (key TEXT PK, value TEXT): `tag`, `verified_at`, `key_hash`, `revoked_before`, `email_claimed_at`, `email_attempts`,
//         `release_log` (JSON array of unix seconds), `last_evicted_at` (unix seconds)
//   seats (seat TEXT PK, created_at INTEGER, deactivated_at INTEGER NULL, last_seen_at INTEGER NULL)
//         `seat` is the seat code as sent, or its HMAC with `SEAT_PEPPER` when that secret is set.
//
// The same class also backs ephemeral `handoff:<hash>` instances for default-browser checkout and
// `recover:<hmac>` instances for email key recovery. Those use only the `meta` table
// (`handoff_kind`, `handoff_seat`, `handoff_session_id`, `handoff_created_at_ms`, `handoff_first_seen_ms`,
// `handoff_last_search_ms`, `handoff_search_count`, or
// `recover_kind`, `recover_claimed_at_ms`), never write `tag` or `seats`, and are wiped by `alarm()`
// 24 hours (handoff) or 15 minutes (recover) after creation.
export class SeatCoordinator extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this._queue = Promise.resolve();
    this._schemaMigrated = false;
  }

  _enqueue(fn) {
    const next = this._queue.then(fn, fn);
    this._queue = next.catch(() => {});
    return next;
  }

  _hasSchema() {
    const rows = this.sql
      .exec(`SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'meta' LIMIT 1`)
      .toArray();
    return rows.length > 0;
  }

  _ensureSchema() {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS seats (seat TEXT PRIMARY KEY, created_at INTEGER NOT NULL, deactivated_at INTEGER, last_seen_at INTEGER)`
    );
    this._migrateSchemaIfNeeded();
  }

  _migrateSchemaIfNeeded() {
    if (this._schemaMigrated) return;
    const cols = this.sql.exec(`PRAGMA table_info(seats)`).toArray().map((r) => String(r.name));
    if (cols.length > 0 && !cols.includes("deactivated_at")) {
      this.sql.exec(`ALTER TABLE seats ADD COLUMN deactivated_at INTEGER`);
    }
    if (cols.length > 0 && !cols.includes("last_seen_at")) {
      this.sql.exec(`ALTER TABLE seats ADD COLUMN last_seen_at INTEGER`);
    }
    this._schemaMigrated = true;
  }

  _readRecord() {
    if (!this._hasSchema()) return null;
    this._migrateSchemaIfNeeded();
    const metaRows = this.sql.exec(`SELECT key, value FROM meta`).toArray();
    const meta = {};
    for (const row of metaRows) {
      meta[row.key] = String(row.value);
    }
    const seatRows = this.sql
      .exec(`SELECT seat FROM seats WHERE deactivated_at IS NULL ORDER BY COALESCE(last_seen_at, created_at) ASC`)
      .toArray();
    const seats = seatRows.map((r) => String(r.seat));
    if (!meta.tag && seats.length === 0 && !meta.email_claimed_at) return null;
    return {
      tag: normalizeTag(meta.tag || ""),
      verifiedAt: Number(meta.verified_at) || 0,
      keyHash: meta.key_hash || "",
      revokedBefore: Number(meta.revoked_before) || 0,
      emailClaimedAt: Number(meta.email_claimed_at) || 0,
      seats,
    };
  }

  _readRevokedBefore() {
    const rows = this.sql.exec(`SELECT value FROM meta WHERE key = 'revoked_before'`).toArray();
    return rows.length ? Number(rows[0].value) || 0 : 0;
  }

  _readReleaseLog() {
    const rows = this.sql.exec(`SELECT value FROM meta WHERE key = 'release_log'`).toArray();
    if (!rows.length) return [];
    try {
      const parsed = JSON.parse(String(rows[0].value));
      return Array.isArray(parsed) ? parsed.filter((t) => Number.isInteger(t)) : [];
    } catch {
      return [];
    }
  }

  // Seat releases (deactivations plus evictions) inside the rolling 365-day window, oldest first.
  _readReleasesInWindow(nowSec) {
    return this._readReleaseLog().filter((t) => nowSec - t < RELEASE_WINDOW_SEC);
  }

  // Call only inside `transactionSync`.
  _appendRelease(nowSec) {
    const log = this._readReleaseLog();
    log.push(nowSec);
    this.sql.exec(
      `INSERT OR REPLACE INTO meta (key, value) VALUES ('release_log', ?)`,
      JSON.stringify(log.slice(-RELEASE_LOG_MAX))
    );
  }

  // Returns the least recently activated active seat when it may be evicted now, otherwise null.
  _evictionCandidate(nowMs) {
    const evictOldestAfterMs = resolveEvictOldestAfterMs(this.env);
    if (evictOldestAfterMs <= 0) return null;
    const nowSec = Math.floor(nowMs / 1000);
    const rows = this.sql
      .exec(
        `SELECT seat, COALESCE(last_seen_at, created_at) AS seen FROM seats WHERE deactivated_at IS NULL ORDER BY seen ASC LIMIT 1`
      )
      .toArray();
    if (!rows.length) return null;
    const victim = rows[0];
    if (nowMs - (Number(victim.seen) || 0) < evictOldestAfterMs) return null;
    const lastRows = this.sql.exec(`SELECT value FROM meta WHERE key = 'last_evicted_at'`).toArray();
    if (lastRows.length) {
      const lastEvictedAt = Number(lastRows[0].value) || 0;
      if (nowSec - lastEvictedAt < Math.floor(evictOldestAfterMs / 1000)) return null;
    }
    if (this._readReleasesInWindow(nowSec).length >= resolveSeatReleasesPerYear(this.env)) return null;
    return victim;
  }

  /**
   * Returns current active seat count for `/thank-you` and atomically claims the backup email slot
   * (`meta.email_claimed_at`) when `wantEmail` is true, the slot is free, and fewer than `EMAIL_MAX_ATTEMPTS`
   * sends were tried (`meta.email_attempts`). Never stores the email address in SQLite.
   */
  async inspectAndClaimThankYou({ keyHash, tag, wantEmail }) {
    return this._enqueue(() => {
      const record = this._readRecord();
      const activeSeats = record ? record.seats.length : 0;
      if (!wantEmail) {
        return { activeSeats, claimedEmailSlot: false };
      }
      if (record && record.emailClaimedAt > 0) {
        return { activeSeats, claimedEmailSlot: false };
      }
      const nowSec = Math.floor(Date.now() / 1000);
      let claimedEmailSlot = false;
      this.ctx.storage.transactionSync(() => {
        this._ensureSchema();
        const existing = this.sql
          .exec(`SELECT 1 AS ok FROM meta WHERE key = 'email_claimed_at' LIMIT 1`)
          .toArray();
        const attemptRows = this.sql.exec(`SELECT value FROM meta WHERE key = 'email_attempts'`).toArray();
        const attempts = attemptRows.length ? Number(attemptRows[0].value) || 0 : 0;
        if (existing.length === 0 && attempts < EMAIL_MAX_ATTEMPTS) {
          this.sql.exec(`INSERT INTO meta (key, value) VALUES ('email_claimed_at', ?)`, String(nowSec));
          this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('email_attempts', ?)`, String(attempts + 1));
          if (!record || !record.tag) {
            this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('tag', ?)`, normalizeTag(tag));
          }
          if (!record || !record.keyHash) {
            this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('key_hash', ?)`, keyHash);
          }
          claimedEmailSlot = true;
        }
      });
      return { activeSeats, claimedEmailSlot };
    });
  }

  /**
   * Frees the backup email slot after a failed send so the next `/thank-you` load can try again.
   * Keeps `meta.email_attempts`, which caps the total number of tries.
   */
  async releaseEmailClaim() {
    return this._enqueue(() => {
      if (!this._hasSchema()) return;
      this.sql.exec(`DELETE FROM meta WHERE key = 'email_claimed_at'`);
    });
  }

  /**
   * Stores an ephemeral `client_reference_id` (`handoff:<hash>`) -> `sessionId` mapping on `/thank-you`
   * (or after fallback search) and schedules a 24-hour alarm to wipe the handoff DO completely.
   * Repeat views of the same session are a no-op (no rewrite, no second alarm).
   */
  async recordCheckoutHandoff({ sessionId, nowMs }) {
    return this._enqueue(async () => {
      const ts = Number(nowMs) || Date.now();
      const meta = this._readHandoffMeta();
      if (meta && meta.handoff_session_id === String(sessionId)) {
        return { ok: true, alreadyRecorded: true };
      }
      this.ctx.storage.transactionSync(() => {
        this._ensureHandoffSchema();
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_kind', '1')`);
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_session_id', ?)`, String(sessionId));
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_created_at_ms', ?)`, String(ts));
      });
      await this._setHandoffAlarm(ts);
      return { ok: true, alreadyRecorded: false };
    });
  }

  /**
   * Binds a `handoff:<hash>` DO instance to the first seat code that polls it, then reads a non-expired
   * `sessionId`, or atomically reserves a 15-second fallback-search slot when `reserveSearchCooldown` is true,
   * the token was first seen at least `HANDOFF_SEARCH_MIN_AGE_MS` earlier (`handoff_first_seen_ms`), and fewer
   * than `HANDOFF_MAX_SEARCHES` searches ran (`handoff_search_count`).
   * Any other seat code gets `seatMismatch: true` and nothing is written.
   */
  async inspectCheckoutHandoff({ nowMs, reserveSearchCooldown, seat }) {
    return this._enqueue(async () => {
      const ts = Number(nowMs) || Date.now();
      const meta = this._readHandoffMeta();
      if (meta && meta.handoff_seat && meta.handoff_seat !== seat) {
        return { sessionId: "", canSearch: false, seatMismatch: true };
      }
      const savedSession = meta ? meta.handoff_session_id || "" : "";
      if (meta && savedSession) {
        const createdAtMs = Number(meta.handoff_created_at_ms) || 0;
        if (createdAtMs > 0 && ts - createdAtMs > HANDOFF_TTL_MS) {
          await this._wipeIfPureHandoff(meta);
          return { sessionId: "", canSearch: false };
        }
      }
      const bindSeat = !meta || !meta.handoff_seat;
      const markFirstSeen = !savedSession && !(meta && meta.handoff_first_seen_ms);
      if (bindSeat || markFirstSeen) {
        this.ctx.storage.transactionSync(() => {
          this._ensureHandoffSchema();
          this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_kind', '1')`);
          if (bindSeat) {
            this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_seat', ?)`, String(seat));
          }
          if (markFirstSeen) {
            this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_first_seen_ms', ?)`, String(ts));
          }
        });
        if (!meta) {
          await this._setHandoffAlarm(ts);
        }
      }
      if (meta && savedSession) {
        return { sessionId: savedSession, canSearch: false };
      }
      if (!reserveSearchCooldown) {
        return { sessionId: "", canSearch: false };
      }
      // `meta` was read before the write above, so a token seen for the first time counts as age 0.
      const firstSeenMs = Number(meta?.handoff_first_seen_ms) || ts;
      if (ts - firstSeenMs < HANDOFF_SEARCH_MIN_AGE_MS) {
        return { sessionId: "", canSearch: false };
      }
      const searchCount = Number(meta?.handoff_search_count) || 0;
      if (searchCount >= HANDOFF_MAX_SEARCHES) {
        return { sessionId: "", canSearch: false };
      }
      const lastSearchMs = Number(meta?.handoff_last_search_ms) || 0;
      if (lastSearchMs > 0 && ts - lastSearchMs < HANDOFF_FALLBACK_SEARCH_COOLDOWN_MS) {
        return { sessionId: "", canSearch: false };
      }

      this.ctx.storage.transactionSync(() => {
        this._ensureHandoffSchema();
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_kind', '1')`);
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_last_search_ms', ?)`, String(ts));
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_search_count', ?)`, String(searchCount + 1));
      });
      return { sessionId: "", canSearch: true };
    });
  }

  /**
   * Durable Object alarm: wipes ephemeral `handoff:` (24h) and `recover:` (15m) instances (`0` bytes on disk).
   * On a `lic:<keyHash>` record it only deletes rows of Macs released more than 30 days ago and re-arms itself for
   * the next such row; it never deletes an active seat or wipes the record.
   */
  async alarm() {
    return this._enqueue(async () => {
      const meta = this._readHandoffMeta();
      if (!meta) return;
      if (await this._wipeIfPureHandoff(meta)) return;
      if (!this._hasSeatsTable()) return;
      const nowSec = Math.floor(Date.now() / 1000);
      this.ctx.storage.transactionSync(() => this._purgeDeactivatedSeats(nowSec));
      const rows = this.sql
        .exec(`SELECT MIN(deactivated_at) AS earliest FROM seats WHERE deactivated_at IS NOT NULL`)
        .toArray();
      const earliest = rows.length ? Number(rows[0].earliest) || 0 : 0;
      if (earliest > 0 && typeof this.ctx.storage.setAlarm === "function") {
        await this.ctx.storage.setAlarm((earliest + DEACTIVATED_SEAT_RETENTION_SEC + 60) * 1000);
      }
    });
  }

  /**
   * Frees the recovery cooldown after a Stripe or email provider failure so the buyer can retry at once.
   */
  async releaseRecoverySlot() {
    return this._enqueue(async () => {
      const meta = this._readHandoffMeta();
      if (meta && meta.recover_kind === "1") {
        await this._wipeIfPureHandoff(meta);
      }
    });
  }

  /**
   * Atomically claims the per-email recovery cooldown slot. Returns `{ claimed: true }` exactly once per
   * `RECOVER_COOLDOWN_MS`; later calls inside the window return `{ claimed: false }`. Stores only a timestamp.
   */
  async claimRecoverySlot({ nowMs }) {
    return this._enqueue(async () => {
      const ts = Number(nowMs) || Date.now();
      const meta = this._readHandoffMeta();
      const claimedAt = Number(meta?.recover_claimed_at_ms) || 0;
      if (claimedAt > 0 && ts - claimedAt < RECOVER_COOLDOWN_MS) {
        return { claimed: false };
      }
      this.ctx.storage.transactionSync(() => {
        this._ensureHandoffSchema();
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('recover_kind', '1')`);
        this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('recover_claimed_at_ms', ?)`, String(ts));
      });
      if (typeof this.ctx.storage.setAlarm === "function") {
        await this.ctx.storage.setAlarm(ts + RECOVER_COOLDOWN_MS);
      }
      return { claimed: true };
    });
  }

  // Ephemeral instances (`handoff:` and `recover:`) only need the `meta` table; skip `seats` and its PRAGMA migration.
  _ensureHandoffSchema() {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  }

  _readHandoffMeta() {
    if (!this._hasSchema()) return null;
    const meta = {};
    for (const r of this.sql.exec(`SELECT key, value FROM meta`).toArray()) {
      meta[r.key] = String(r.value);
    }
    return meta;
  }

  // A pure ephemeral instance carries a `handoff_kind` or `recover_kind` marker and has never recorded a license tag or seat.
  _isPureHandoff(meta) {
    if (!meta || meta.tag) return false;
    if (meta.handoff_kind !== "1" && meta.recover_kind !== "1") return false;
    const seatTable = this.sql
      .exec(`SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'seats' LIMIT 1`)
      .toArray();
    if (seatTable.length === 0) return true;
    return this.sql.exec(`SELECT 1 AS ok FROM seats LIMIT 1`).toArray().length === 0;
  }

  async _wipeIfPureHandoff(meta) {
    if (!this._isPureHandoff(meta)) return false;
    await this.ctx.storage.deleteAll();
    this._schemaMigrated = false;
    return true;
  }

  async _setHandoffAlarm(fromMs) {
    if (typeof this.ctx.storage.setAlarm === "function") {
      await this.ctx.storage.setAlarm(fromMs + HANDOFF_TTL_MS);
    }
  }

  _hasSeatsTable() {
    return (
      this.sql.exec(`SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'seats' LIMIT 1`).toArray().length > 0
    );
  }

  // Deletes rows of Macs deactivated or evicted more than `DEACTIVATED_SEAT_RETENTION_SEC` ago. Never touches an
  // active row. `deactivated_at` is in seconds (`created_at` and `last_seen_at` are in milliseconds).
  _purgeDeactivatedSeats(nowSec) {
    this._migrateSchemaIfNeeded();
    if (!this._hasSeatsTable()) return;
    this.sql.exec(
      `DELETE FROM seats WHERE deactivated_at IS NOT NULL AND deactivated_at <= ?`,
      nowSec - DEACTIVATED_SEAT_RETENTION_SEC
    );
  }

  // Arms the purge alarm after a seat release when no alarm is pending.
  async _armPurgeAlarmIfIdle(nowSec) {
    if (typeof this.ctx.storage.getAlarm !== "function" || typeof this.ctx.storage.setAlarm !== "function") return;
    const pending = await this.ctx.storage.getAlarm();
    if (pending === null || pending === undefined) {
      await this.ctx.storage.setAlarm((nowSec + DEACTIVATED_SEAT_RETENTION_SEC + 60) * 1000);
    }
  }

  /**
   * Wipes this license record on request (`action: "erase"`) or after a definite invalid answer on `/thank-you`.
   * Refuses a record whose stored `key_hash` belongs to another key.
   */
  async eraseLicenseRecord({ keyHash }) {
    return this._enqueue(async () => {
      if (!this._hasSchema()) return { erased: false };
      const rows = this.sql.exec(`SELECT value FROM meta WHERE key = 'key_hash'`).toArray();
      if (rows.length > 0 && String(rows[0].value) !== keyHash) return { erased: false };
      if (typeof this.ctx.storage.deleteAlarm === "function") {
        await this.ctx.storage.deleteAlarm();
      }
      await this.ctx.storage.deleteAll();
      this._schemaMigrated = false;
      return { erased: true };
    });
  }

  // Call only inside `transactionSync`. Renames a row stored under the raw seat code to its peppered value, so
  // turning `SEAT_PEPPER` on never uses an extra seat.
  _migrateStoredSeat(seat, storedSeat) {
    if (storedSeat === seat) return;
    const raw = this.sql.exec(`SELECT 1 AS ok FROM seats WHERE seat = ? LIMIT 1`, seat).toArray();
    if (raw.length === 0) return;
    const peppered = this.sql.exec(`SELECT 1 AS ok FROM seats WHERE seat = ? LIMIT 1`, storedSeat).toArray();
    if (peppered.length > 0) return;
    this.sql.exec(`UPDATE seats SET seat = ? WHERE seat = ?`, storedSeat, seat);
  }

  async mutate(params) {
    return this._enqueue(() => this._mutateExclusive(params));
  }

  async _mutateExclusive({ action, rawKey, keyHash, seat, storedSeat: storedSeatParam, tag, ticketTag, ticketIssued, clientMinIssued = 0 }) {
    const storedSeat = storedSeatParam || seat;
    const maxSeats = resolveMaxSeats(this.env);
    let record = this._readRecord();

    if (action === "deactivate") {
      if (!record || (!record.tag && record.seats.length === 0)) {
        return { status: 404, body: { error: "unknown_key" } };
      }
      if (record.keyHash && record.keyHash !== keyHash) {
        return { status: 403, body: { error: "invalid_ticket" } };
      }
      if (typeof ticketTag !== "string" || !ticketTag || normalizeTag(ticketTag) !== record.tag) {
        return { status: 403, body: { error: "invalid_ticket" } };
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const minWatermark = Math.max(nowSec, Number(ticketIssued) || 0);
      let revokedBefore = record.revokedBefore;
      let releaseLimitRetryAfterSec = 0;
      let released = false;
      this.ctx.storage.transactionSync(() => {
        this._migrateSchemaIfNeeded();
        this._purgeDeactivatedSeats(nowSec);
        this._migrateStoredSeat(seat, storedSeat);
        const active = this.sql
          .exec(`SELECT 1 AS ok FROM seats WHERE seat = ? AND deactivated_at IS NULL LIMIT 1`, storedSeat)
          .toArray();
        if (active.length > 0) {
          const used = this._readReleasesInWindow(nowSec);
          const budget = resolveSeatReleasesPerYear(this.env);
          if (used.length >= budget) {
            releaseLimitRetryAfterSec =
              budget === 0 ? RELEASE_WINDOW_SEC : Math.max(1, used[used.length - budget] + RELEASE_WINDOW_SEC - nowSec);
            return;
          }
          this.sql.exec(`UPDATE seats SET deactivated_at = ? WHERE seat = ?`, nowSec, storedSeat);
          revokedBefore = Math.max(this._readRevokedBefore(), minWatermark);
          this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('revoked_before', ?)`, String(revokedBefore));
          this._appendRelease(nowSec);
          released = true;
        }
      });
      if (released) {
        await this._armPurgeAlarmIfIdle(nowSec);
      }
      if (releaseLimitRetryAfterSec > 0) {
        return { status: 429, body: { error: "release_limit", retryAfterSec: releaseLimitRetryAfterSec } };
      }
      return { status: 200, body: { ok: true, revokedBefore } };
    }

    const now = Date.now();
    const isExistingSeat = Boolean(record && (record.seats.includes(storedSeat) || record.seats.includes(seat)));
    const canEvictOldest = Boolean(record) && this._evictionCandidate(now) !== null;

    if (record && !isExistingSeat && record.seats.length >= maxSeats && !canEvictOldest && now - record.verifiedAt <= REVERIFY_TTL_MS) {
      return { status: 409, body: { error: "seat_limit_reached", maxSeats } };
    }

    const needsStoreCheck = !record || record.verifiedAt === 0 || !isExistingSeat || now - record.verifiedAt > REVERIFY_TTL_MS;
    let updatedVerifiedAt = record ? record.verifiedAt : 0;

    if (needsStoreCheck) {
      const valid = await verifyKeyWithStore(rawKey, keyHash, this.env, {
        bypassRecentValidCache: Boolean(record && record.verifiedAt > 0),
      });

      if (valid === "rate_limited") {
        return { status: 429, retryAfter: 10, body: { error: "rate_limited" } };
      } else if (valid === false) {
        if (this._hasSchema()) {
          await this.ctx.storage.deleteAll();
          this._schemaMigrated = false;
        }
        return { status: 403, cacheNegative: true, body: { error: "invalid_key" } };
      } else if (valid === "pending") {
        return { status: 409, retryAfter: 10, body: { error: "payment_pending" } };
      } else if (valid === null) {
        // Stripe unreachable: re-issue an existing seat only while the last successful check is recent.
        if (!isExistingSeat || now - record.verifiedAt >= OUTAGE_REMINT_MAX_AGE_MS) {
          return { status: 502, body: { error: "upstream_unavailable" } };
        }
      } else if (valid === true) {
        updatedVerifiedAt = now;
      } else if (valid === "payment_disputed") {
        // Open dispute: refuse new seats and stale seats, never wipe; keep re-issuing a recently verified seat.
        if (!isExistingSeat || now - record.verifiedAt >= OUTAGE_REMINT_MAX_AGE_MS) {
          return { status: 403, body: { error: "payment_disputed" } };
        }
      } else if (valid !== true) {
        return { status: 502, body: { error: "upstream_unavailable" } };
      }
    }

    const currentSeats = record ? record.seats : [];
    if (!isExistingSeat && currentSeats.length >= maxSeats && !canEvictOldest) {
      return { status: 409, body: { error: "seat_limit_reached", maxSeats } };
    }

    const effectiveTag = record && record.tag ? record.tag : normalizeTag(tag);
    const priorRevokedBefore = record ? record.revokedBefore : 0;
    const nowSec = Math.floor(now / 1000);
    const ticketFloor = canEvictOldest && !isExistingSeat && currentSeats.length >= maxSeats
      ? Math.max(priorRevokedBefore, nowSec)
      : priorRevokedBefore;

    // Sign before writing to SQLite so a bad key configuration does not consume a seat.
    let ticket;
    try {
      ticket = await mintSeatTicket(effectiveTag, seat, this.env, ticketFloor, clientMinIssued);
    } catch {
      return { status: 500, body: { error: "signing_error" } };
    }

    let seatsUsed = 0;
    let limitHit = false;
    let evicted = false;
    let revokedBefore = priorRevokedBefore;
    this.ctx.storage.transactionSync(() => {
      this._ensureSchema();
      this._purgeDeactivatedSeats(nowSec);
      this._migrateStoredSeat(seat, storedSeat);
      let rows = this.sql
        .exec(`SELECT seat, created_at FROM seats WHERE deactivated_at IS NULL ORDER BY created_at ASC`)
        .toArray();
      const alreadyIn = rows.some((r) => String(r.seat) === storedSeat);

      if (!alreadyIn && rows.length >= maxSeats) {
        const victim = this._evictionCandidate(now);
        if (victim !== null) {
          this.sql.exec(`UPDATE seats SET deactivated_at = ? WHERE seat = ?`, nowSec, String(victim.seat));
          revokedBefore = Math.max(this._readRevokedBefore(), nowSec);
          this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('revoked_before', ?)`, String(revokedBefore));
          this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('last_evicted_at', ?)`, String(nowSec));
          this._appendRelease(nowSec);
          evicted = true;
          rows = rows.filter((r) => String(r.seat) !== String(victim.seat));
        } else {
          limitHit = true;
          return;
        }
      }

      if (!alreadyIn) {
        const dormant = this.sql.exec(`SELECT 1 AS ok FROM seats WHERE seat = ? LIMIT 1`, storedSeat).toArray();
        if (dormant.length > 0) {
          this.sql.exec(`UPDATE seats SET deactivated_at = NULL, last_seen_at = ? WHERE seat = ?`, now, storedSeat);
        } else {
          this.sql.exec(`INSERT INTO seats (seat, created_at, deactivated_at) VALUES (?, ?, NULL)`, storedSeat, now);
        }
        seatsUsed = rows.length + 1;
      } else {
        this.sql.exec(`UPDATE seats SET last_seen_at = ? WHERE seat = ?`, now, storedSeat);
        seatsUsed = rows.length;
      }
      this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('tag', ?)`, effectiveTag);
      this.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('key_hash', ?)`, keyHash);
      this.sql.exec(
        `INSERT OR REPLACE INTO meta (key, value) VALUES ('verified_at', ?)`,
        String(updatedVerifiedAt || now)
      );
      revokedBefore = this._readRevokedBefore();
    });

    if (evicted) {
      await this._armPurgeAlarmIfIdle(nowSec);
    }
    if (limitHit) {
      return { status: 409, body: { error: "seat_limit_reached", maxSeats } };
    }

    return {
      status: 200,
      body: { ticket, seatsUsed, maxSeats, revokedBefore },
    };
  }
}

// JSON for a value placed inside an inline <script>: no `<`, `>`, `&`, U+2028, or U+2029 survives literally.
function jsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

// Landing page for email buttons. The server never sees the key: it lives in `location.hash`, is checked against
// the purchase-key shape, shown for copying, and handed to `myapp://activate?key=...` on a Mac.
function renderOpenPage(env) {
  const appNameRaw = resolveAppName(env);
  const appNameHtml = escapeHtml(appNameRaw);
  const urlScheme = resolveAppUrlScheme(env);
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(18)));
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow">
<title>Open ${appNameHtml}</title>
<style>
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0d1017; color: #f5f7fa;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
  }
  .card {
    max-width: 440px; width: 90%; padding: 28px; border-radius: 18px;
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.14);
    box-shadow: 0 24px 60px rgba(0,0,0,0.45); text-align: center;
  }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { font-size: 13.5px; color: rgba(255,255,255,0.72); line-height: 1.5; margin: 0 0 18px; }
  .key-box {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
    word-break: break-all; padding: 11px; border-radius: 10px;
    background: rgba(0,0,0,0.45); border: 1px solid rgba(255,255,255,0.18);
    color: #ffd479; margin-bottom: 10px; user-select: all;
  }
  .btn {
    display: inline-block; width: 100%; box-sizing: border-box; padding: 11px 16px;
    border-radius: 9px; border: none; font-size: 13.5px; font-weight: 600;
    cursor: pointer; text-decoration: none; margin-bottom: 8px;
  }
  .btn-primary { background: #0a84ff; color: #fff; }
  .btn-secondary { background: rgba(255,255,255,0.1); color: #fff; }
</style>
</head>
<body>
  <div class="card">
    <h1>Opening ${appNameHtml}</h1>
    <p id="msg">If ${appNameHtml} does not open, click the button, or copy the key and paste it into ${appNameHtml} &rsaquo; Settings.</p>
    <a class="btn btn-primary" id="activateBtn" href="${escapeHtml(urlScheme)}://activate">Open in ${appNameHtml}</a>
    <div class="key-box" id="licKey"></div>
    <button type="button" class="btn btn-secondary" id="copyBtn">Copy Key</button>
  </div>
  <script nonce="${nonce}">
    (function () {
      var scheme = ${jsonForScript(urlScheme)};
      var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
      var key = (params.get("key") || "").trim();
      if (!/^cs_(live|test)_[A-Za-z0-9_]+$/.test(key)) key = "";
      var keyEl = document.getElementById("licKey");
      var actBtn = document.getElementById("activateBtn");
      var copyBtn = document.getElementById("copyBtn");
      if (!key) {
        document.getElementById("msg").textContent = "This link has no valid license key. Copy the key from your email and paste it into the app.";
        keyEl.remove();
        copyBtn.remove();
        return;
      }
      var deepLink = scheme + "://activate?key=" + encodeURIComponent(key);
      keyEl.textContent = key;
      actBtn.setAttribute("href", deepLink);
      copyBtn.addEventListener("click", function () {
        try { navigator.clipboard.writeText(key); } catch (_) {}
        copyBtn.textContent = "Copied";
      });
      var ua = navigator.userAgent || "";
      var isMac = /Macintosh|Mac OS X/i.test(ua) && !/iPhone|iPad|iPod/i.test(ua);
      if (isMac) {
        setTimeout(function () { window.location.href = deepLink; }, 200);
      }
    })();
  </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: securityHeaders({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    }),
  });
}

function renderThankYouPage(licenseKey, env, orderTag = "") {
  const safeKey = (licenseKey || "").replace(/[^A-Za-z0-9_.-]/g, "");
  const appNameRaw = resolveAppName(env);
  const appNameHtml = escapeHtml(appNameRaw);
  const urlScheme = resolveAppUrlScheme(env);
  const maxSeats = resolveMaxSeats(env);
  const deepLink = safeKey ? `${urlScheme}://activate?key=${encodeURIComponent(safeKey)}` : `${urlScheme}://activate`;
  const fileSafeSlug = appNameRaw.replace(/[^A-Za-z0-9_-]/g, "") || "App";
  const expiredFallbackText =
    "This checkout page has expired. Copy your license key from the app settings or your backup email.";
  // `POST /` rejects every request carrying an `Origin` header, and browsers always send one on same-origin
  // fetch POSTs, so the page cannot call the recovery endpoint itself. Point the buyer at the in-app field instead.
  const recoveryConfigured = Boolean(env.STRIPE_SECRET_KEY && env.RESEND_API_KEY && env.RECEIPT_FROM_EMAIL);
  const recoverHintHtml =
    !safeKey && recoveryConfigured
      ? `<p class="caption" id="recoverHint">Lost it? Open ${appNameHtml}, paste the email you paid with into the license field, and click Email Key.</p>`
      : "";

  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(18)));
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow">
<title>${appNameHtml} - License Key</title>
<style>
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0d1017; color: #f5f7fa;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
  }
  .card {
    max-width: 440px; width: 90%; padding: 28px; border-radius: 18px;
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.14);
    box-shadow: 0 24px 60px rgba(0,0,0,0.45); text-align: center;
  }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { font-size: 13.5px; color: rgba(255,255,255,0.72); line-height: 1.5; margin: 0 0 18px; }
  .key-box {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
    word-break: break-all; padding: 11px; border-radius: 10px;
    background: rgba(0,0,0,0.45); border: 1px solid rgba(255,255,255,0.18);
    color: #ffd479; margin-bottom: 10px; user-select: all;
  }
  .btn {
    display: inline-block; width: 100%; box-sizing: border-box; padding: 11px 16px;
    border-radius: 9px; border: none; font-size: 13.5px; font-weight: 600;
    cursor: pointer; text-decoration: none; margin-bottom: 8px;
  }
  .btn-primary { background: #0a84ff; color: #fff; }
  .btn-secondary { background: rgba(255,255,255,0.1); color: #fff; }
  .row { display: flex; gap: 8px; }
  .row .btn { margin-bottom: 0; font-size: 12.5px; padding: 9px 12px; }
  .caption { font-size: 11.5px; color: rgba(255,255,255,0.48); margin: 14px 0 6px; }
</style>
</head>
<body>
  <div class="card">
    <h1>Thank you for buying ${appNameHtml}</h1>
    <p>Opening <b>${appNameHtml}</b> with your license key pre-filled. Save a copy of your key below (Stripe email receipts do not include this key).</p>
    <a class="btn btn-primary" id="activateBtn" href="${deepLink}">Open in ${appNameHtml}</a>
    <div class="caption">License Key (up to ${maxSeats} Macs):</div>
    <div class="key-box" id="licKey">${safeKey || expiredFallbackText}</div>
    ${recoverHintHtml}
    <div class="row">
      <button type="button" class="btn btn-secondary" id="copyBtn">Copy Key</button>
      <button type="button" class="btn btn-secondary" id="saveBtn">Save .txt File</button>
      <button type="button" class="btn btn-secondary" id="clearBtn">Clear saved key</button>
    </div>
  </div>
  <script nonce="${nonce}">
    (function () {
      var serverKey = ${jsonForScript(safeKey)};
      var key = serverKey;
      var scheme = ${jsonForScript(urlScheme)};
      var appTitle = ${jsonForScript(appNameRaw)};
      var fileName = ${jsonForScript(`${fileSafeSlug}-License.txt`)};
      var seatCap = ${jsonForScript(maxSeats)};
      var orderTag = ${jsonForScript(orderTag)};
      var storageSlot = "seatstamp_backup_key_" + scheme + "_" + orderTag;
      var maxAgeMs = 30 * 86400000;
      try {
        if (serverKey) {
          localStorage.setItem(storageSlot, JSON.stringify({ k: serverKey, t: Date.now() }));
        } else {
          var raw = localStorage.getItem(storageSlot);
          if (raw) {
            var found = "";
            try {
              var rec = JSON.parse(raw);
              var age = rec && typeof rec.t === "number" ? Date.now() - rec.t : -1;
              if (rec && typeof rec.k === "string" && /^cs_(live|test)_[A-Za-z0-9_]+$/.test(rec.k) && age >= 0 && age <= maxAgeMs) {
                found = rec.k;
              }
            } catch (_) {}
            if (found) {
              key = found;
            } else {
              localStorage.removeItem(storageSlot);
            }
          }
        }
      } catch (_) {}
      var deepLink = key ? (scheme + "://activate?key=" + encodeURIComponent(key)) : (scheme + "://activate");
      var keyEl = document.getElementById("licKey");
      var actBtn = document.getElementById("activateBtn");
      if (key && keyEl) keyEl.textContent = key;
      var hintEl = document.getElementById("recoverHint");
      if (key && hintEl) hintEl.remove();
      if (actBtn) actBtn.setAttribute("href", deepLink);
      var copyBtn = document.getElementById("copyBtn");
      var saveBtn = document.getElementById("saveBtn");
      var clearBtn = document.getElementById("clearBtn");
      copyBtn.addEventListener("click", function () {
        if (!key) return;
        try { navigator.clipboard.writeText(key); } catch (_) {}
        copyBtn.textContent = "Copied";
      });
      saveBtn.addEventListener("click", function () {
        if (!key) return;
        var text = appTitle + " License Key (Up to " + seatCap + " Macs):\\n" + key + "\\n\\nActivation link:\\n" + deepLink + "\\n";
        var blob = new Blob([text], { type: "text/plain" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = fileName;
        a.click();
      });
      clearBtn.addEventListener("click", function () {
        try {
          localStorage.removeItem(storageSlot);
        } catch (_) {}
        key = "";
        deepLink = scheme + "://activate";
        if (keyEl) keyEl.textContent = "Saved key cleared from this browser.";
        if (actBtn) actBtn.setAttribute("href", deepLink);
        clearBtn.textContent = "Cleared";
      });
      var ua = navigator.userAgent || "";
      var isMac = /Macintosh|Mac OS X/i.test(ua) && !/iPhone|iPad|iPod/i.test(ua);
      if (serverKey && isMac) {
        setTimeout(function () { window.location.href = deepLink; }, 200);
      }
    })();
  </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: securityHeaders({
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    }),
  });
}

async function readBodyBounded(request, limit) {
  if (!request.body) {
    return "";
  }
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > limit) {
        try {
          await reader.cancel();
        } catch {}
        return null;
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {}
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder("utf-8").decode(merged);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const keyHashDomain = resolveKeyHashDomain(env);

    // GET /thank-you?session_id={CHECKOUT_SESSION_ID}
    if (request.method === "GET" && (url.pathname === "/thank-you" || url.pathname === "/success")) {
      const sessionId = (url.searchParams.get("session_id") || "").trim();
      if (!STRIPE_SESSION_RE.test(sessionId) || (isLiveStripeSecret(env.STRIPE_SECRET_KEY) && !sessionId.startsWith("cs_live_"))) {
        return new Response("Invalid or missing Stripe session_id.", {
          status: 400,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      if (!env.STRIPE_SECRET_KEY) {
        return new Response("Activation service unconfigured.", {
          status: 503,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      const keyHash = await sha256Hex(keyHashDomain + sessionId);
      if (isNegativeCached(keyHash)) {
        return new Response("Payment session not completed.", {
          status: 403,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      if (!(await allowThankYouAttempt(request))) {
        return new Response("Too many requests. Please try again in 60 seconds.", {
          status: 429,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8", "Retry-After": "60" }),
        });
      }

      const outMeta = { createdSec: 0, customerEmail: "", clientReferenceId: "" };
      // The recent-valid cache never holds the email address, so a configured backup email needs a fresh lookup.
      const emailConfigured = Boolean(env.RESEND_API_KEY && env.RECEIPT_FROM_EMAIL);
      const valid = await verifyKeyWithStore(sessionId, keyHash, env, { outMeta, bypassRecentValidCache: emailConfigured });
      if (valid === false) {
        // A definite "not paid" answer from Stripe: wipe any license record of this key.
        if (env.SEAT_DO) {
          const wipe = env.SEAT_DO.get(env.SEAT_DO.idFromName("lic:" + keyHash))
            .eraseLicenseRecord({ keyHash })
            .catch(() => {});
          if (ctx && typeof ctx.waitUntil === "function") {
            ctx.waitUntil(wipe);
          } else {
            await wipe;
          }
        }
        return new Response("Payment session not completed.", {
          status: 403,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      if (valid === "payment_disputed") {
        return new Response("This payment is under dispute. Contact the seller.", {
          status: 403,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      if (valid === "rate_limited") {
        return new Response("High traffic. Please refresh this page in 10 seconds.", {
          status: 429,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8", "Retry-After": "10" }),
        });
      }
      if (valid === "pending") {
        return new Response("Your payment is still processing. Reload this page in a moment.", {
          status: 202,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8", "Retry-After": "10" }),
        });
      }
      if (valid !== true) {
        return new Response("Verifying your payment with Stripe. Please refresh this page in a moment.", {
          status: 503,
          headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8", "Retry-After": "5" }),
        });
      }

      const maxSeats = resolveMaxSeats(env);
      const windowSec = resolveThankYouWindowSeconds(env);
      const nowSec = Math.floor(Date.now() / 1000);
      const expiredByAge = outMeta.createdSec > 0 && nowSec - outMeta.createdSec > windowSec;
      const handoffFresh = outMeta.createdSec > 0 && nowSec - outMeta.createdSec <= Math.min(windowSec, HANDOFF_TTL_MS / 1000);

      let activeSeats = 0;
      const orderTag = keyHash.slice(0, 16).toUpperCase();
      if (env.SEAT_DO) {
        const doName = "lic:" + keyHash;
        const defaultTag = orderTag;
        const stub = env.SEAT_DO.get(env.SEAT_DO.idFromName(doName));
        const wantEmail = Boolean(env.RESEND_API_KEY && env.RECEIPT_FROM_EMAIL && outMeta.customerEmail);
        // The handoff record and the seat inspection live in different DOs and do not depend on each other.
        const handoffPromise = HANDOFF_TOKEN_RE.test(outMeta.clientReferenceId) && handoffFresh
          ? (async () => {
              const handoffDoName = await deriveHandoffDoName(outMeta.clientReferenceId, keyHashDomain);
              const handoffStub = env.SEAT_DO.get(env.SEAT_DO.idFromName(handoffDoName));
              await handoffStub.recordCheckoutHandoff({ sessionId, nowMs: Date.now() });
            })()
          : Promise.resolve();
        const [doState] = await Promise.all([
          stub.inspectAndClaimThankYou({ keyHash, tag: defaultTag, wantEmail }),
          handoffPromise,
        ]);
        activeSeats = doState.activeSeats;
        if (doState.claimedEmailSlot && outMeta.customerEmail) {
          const emailPromise = sendBackupEmail(outMeta.customerEmail, sessionId, keyHash, env, url.origin)
            .then((sent) => (sent ? undefined : stub.releaseEmailClaim()))
            .catch(() => {});
          if (ctx && typeof ctx.waitUntil === "function") {
            ctx.waitUntil(emailPromise);
          } else {
            await emailPromise;
          }
        }
      }

      const expiredBySeats = activeSeats >= maxSeats;
      const keyForPage = expiredByAge || expiredBySeats ? "" : sessionId;
      return renderThankYouPage(keyForPage, env, orderTag);
    }

    // GET /open#key=cs_live_... : the https target of email buttons. Static; the key stays in the fragment.
    if (url.pathname === "/open") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405, headers: securityHeaders({ Allow: "GET, HEAD" }) });
      }
      return renderOpenPage(env);
    }

    if (url.pathname === "/thank-you" || url.pathname === "/success") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: securityHeaders({ Allow: "GET" }),
      });
    }
    if (url.pathname !== "/") {
      // A distinct answer, so a client configured with a path reports a setup problem instead of a wrong key.
      return jsonResponse({ error: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: securityHeaders({ Allow: "POST" }),
      });
    }

    if (request.headers.has("Origin") || request.headers.get("Sec-Fetch-Site") === "cross-site") {
      return jsonResponse({ error: "forbidden_origin" }, 403);
    }
    // Optional rate-limit binding: approximate and per Cloudflare location. The key is a digest, never the IP.
    // A missing binding or a thrown error lets the request through.
    if (env.POST_RATE_LIMITER && typeof env.POST_RATE_LIMITER.limit === "function") {
      let allowed = true;
      try {
        const ip = request.headers.get("CF-Connecting-IP") || "anon";
        const rlKey = (await sha256Hex(keyHashDomain + "rl|" + ip)).slice(0, 32);
        const outcome = await env.POST_RATE_LIMITER.limit({ key: rlKey });
        allowed = !(outcome && outcome.success === false);
      } catch {
        allowed = true;
      }
      if (!allowed) {
        return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "60" });
      }
    }
    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    if (!contentType.startsWith("application/json")) {
      return jsonResponse({ error: "unsupported_media_type" }, 415);
    }

    const contentLen = Number(request.headers.get("content-length") || "0");
    if (contentLen > MAX_BODY_BYTES) {
      return jsonResponse({ error: "payload_too_large" }, 413);
    }

    let rawText;
    try {
      rawText = await readBodyBounded(request, MAX_BODY_BYTES);
    } catch {
      return jsonResponse({ error: "bad_body" }, 400);
    }
    if (rawText === null) {
      return jsonResponse({ error: "payload_too_large" }, 413);
    }

    let body;
    try {
      body = JSON.parse(rawText);
    } catch {
      return jsonResponse({ error: "bad_json" }, 400);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return jsonResponse({ error: "bad_json" }, 400);
    }

    const action = typeof body.action === "string" ? body.action.trim() : "";
    const rawKey = typeof body.key === "string" ? body.key.trim() : "";
    const seat = typeof body.seat === "string" ? body.seat.trim().toLowerCase() : "";
    const ticket = typeof body.ticket === "string" ? body.ticket.trim() : "";
    const handoff = typeof body.handoff === "string" ? body.handoff.trim() : "";
    const clientMinIssued = Number.isSafeInteger(body.minIssued) && body.minIssued >= 0 ? body.minIssued : 0;

    if (action === "recover") {
      if (!env.STRIPE_SECRET_KEY || !env.RESEND_API_KEY || !env.RECEIPT_FROM_EMAIL) {
        return jsonResponse({ error: "recovery_unconfigured" }, 501);
      }
      const email = normalizeRecoveryEmail(body.email);
      if (!email) {
        return jsonResponse({ error: "invalid_params" }, 400);
      }
      if (!(await allowRecoverAttempt(request))) {
        return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "60" });
      }
      if (!env.SEAT_DO) {
        return jsonResponse({ error: "storage_unconfigured" }, 500);
      }

      // The Stripe budget slot for the first lookup is taken before the cooldown, so a busy isolate never
      // arms a cooldown it cannot serve. This answer does not depend on the email.
      if (!consumeGlobalStoreSlot()) {
        return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "10" });
      }

      // Everything below returns the same 200 regardless of whether the email exists or was recently asked for.
      const nowMs = Date.now();
      const { doName, emailHmac } = await deriveRecoverDoName(email.trimmed, email.lower, keyHashDomain, env);
      const recoverStub = env.SEAT_DO.get(env.SEAT_DO.idFromName(doName));
      const slot = await recoverStub.claimRecoverySlot({ nowMs });
      if (slot.claimed) {
        const job = runEmailRecovery(
          { trimmedEmail: email.trimmed, lowerEmail: email.lower, emailHmac, nowMs, origin: url.origin },
          env,
          () => recoverStub.releaseRecoverySlot()
        ).catch(() => {});
        if (ctx && typeof ctx.waitUntil === "function") {
          ctx.waitUntil(job);
        } else {
          await job;
        }
      }
      return jsonResponse({ ok: true }, 200);
    }

    if (action === "claim_checkout") {
      if (!HANDOFF_TOKEN_RE.test(handoff) || !/^[0-9a-f]{16}$/.test(seat)) {
        return jsonResponse({ error: "invalid_params" }, 400);
      }
      if (!(await allowClaimAttempt(request))) {
        return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "30" });
      }
      if (!env.SEAT_DO) {
        return jsonResponse({ error: "storage_unconfigured" }, 500);
      }

      const handoffDoName = await deriveHandoffDoName(handoff, keyHashDomain);
      const handoffStub = env.SEAT_DO.get(env.SEAT_DO.idFromName(handoffDoName));
      const nowMs = Date.now();
      const handoffState = await handoffStub.inspectCheckoutHandoff({
        nowMs,
        reserveSearchCooldown: Boolean(body.fallbackSearch === true && env.STRIPE_SECRET_KEY),
        seat,
      });
      if (handoffState.seatMismatch) return jsonResponse({ error: "handoff_seat_mismatch" }, 403);
      let sessionId = handoffState.sessionId;

      if (!sessionId && handoffState.canSearch && env.STRIPE_SECRET_KEY) {
        const found = await findStripeSessionByHandoff(handoff, keyHashDomain, env);
        if (found === "rate_limited") {
          return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "10" });
        }
        if (found === null) {
          // Stripe unreachable, or the restricted key lacks list permission: surface it instead of
          // masquerading as "not paid yet" so misconfiguration is visible to the client.
          return jsonResponse({ error: "upstream_unavailable" }, 502, { "Retry-After": "10" });
        }
        if (found) {
          sessionId = found;
          await handoffStub.recordCheckoutHandoff({ sessionId, nowMs: Date.now() });
        }
      }

      if (!sessionId) {
        return jsonResponse({ status: "pending" }, 202);
      }

      const keyHash = await sha256Hex(keyHashDomain + sessionId);
      if (isNegativeCached(keyHash)) {
        return jsonResponse({ error: "invalid_key" }, 403);
      }
      const doName = "lic:" + keyHash;
      const defaultTag = keyHash.slice(0, 16).toUpperCase();
      const licStub = env.SEAT_DO.get(env.SEAT_DO.idFromName(doName));
      const res = await licStub.mutate({
        action: "activate",
        rawKey: sessionId,
        keyHash,
        seat,
        storedSeat: await storedSeatId(seat, env),
        tag: defaultTag,
        clientMinIssued,
      });
      if (res.cacheNegative) {
        rememberNegativeKey(keyHash);
      }
      if (res.status === 409 && res.body.error === "payment_pending") {
        return jsonResponse({ status: "pending" }, 202);
      }
      const extra = res.retryAfter ? { "Retry-After": String(res.retryAfter) } : {};
      if (res.status === 200) {
        return jsonResponse({ status: "activated", key: sessionId, ...res.body }, 200, extra);
      }
      return jsonResponse(res.body, res.status, extra);
    }

    if (action === "erase") {
      const adminToken = String(env.ADMIN_TOKEN || "").trim();
      if (adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
        return jsonResponse({ error: "erase_unconfigured" }, 501);
      }
      if (!(await allowClientAttempt(request, "erase", ERASE_RATE_LIMIT_PER_MIN))) {
        return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "60" });
      }
      if (
        typeof body.key !== "string" ||
        rawKey.length < 16 ||
        rawKey.length > MAX_KEY_LENGTH ||
        typeof body.adminToken !== "string" ||
        body.adminToken.length > MAX_ADMIN_TOKEN_LENGTH
      ) {
        return jsonResponse({ error: "invalid_params" }, 400);
      }
      if (!(await digestsEqual(body.adminToken.trim(), adminToken))) {
        return jsonResponse({ error: "forbidden" }, 403);
      }
      if (!env.SEAT_DO) {
        return jsonResponse({ error: "storage_unconfigured" }, 500);
      }
      const keyHash = await sha256Hex(keyHashDomain + rawKey);
      const stub = env.SEAT_DO.get(env.SEAT_DO.idFromName("lic:" + keyHash));
      const result = await stub.eraseLicenseRecord({ keyHash });
      negativeKeyCache.delete(keyHash);
      recentValidSessionCache.delete(keyHash);
      return jsonResponse({ ok: true, erased: Boolean(result && result.erased) }, 200);
    }

    if (!rawKey || rawKey.length > MAX_KEY_LENGTH || !/^[0-9a-f]{16}$/.test(seat)) {
      return jsonResponse({ error: "invalid_params" }, 400);
    }
    if (action !== "activate" && action !== "deactivate") {
      return jsonResponse({ error: "unknown_action" }, 400);
    }

    if (classifyKeyFormat(rawKey, env) === "invalid") {
      return jsonResponse({ error: "invalid_key" }, 403);
    }

    const keyHash = await sha256Hex(keyHashDomain + rawKey);
    if (action === "activate" && isNegativeCached(keyHash)) {
      return jsonResponse({ error: "invalid_key" }, 403);
    }

    if (!(await allowClientStoreAttempt(request))) {
      return jsonResponse({ error: "rate_limited" }, 429, { "Retry-After": "30" });
    }

    let ticketTag;
    let ticketIssued = 0;
    if (action === "deactivate") {
      if (ticket) {
        // A missing or malformed key secret is a server error: answering 403 would make the client drop its
        // queued deactivation and leave the seat occupied for good.
        try {
          await getVerifyKeys(env);
        } catch {
          return jsonResponse({ error: "signing_error" }, 500);
        }
        const verified = await verifySeatTicket(ticket, seat, env);
        if (!verified.ok) {
          return jsonResponse({ error: "invalid_ticket" }, 403);
        }
        ticketTag = verified.tag;
        ticketIssued = verified.issued;
      } else {
        return jsonResponse({ error: "ticket_required" }, 400);
      }
    }

    const doName = "lic:" + keyHash;
    const defaultTag = keyHash.slice(0, 16).toUpperCase();

    if (!env.SEAT_DO) {
      return jsonResponse({ error: "storage_unconfigured" }, 500);
    }
    const stub = env.SEAT_DO.get(env.SEAT_DO.idFromName(doName));
    const res = await stub.mutate({
      action,
      rawKey,
      keyHash,
      seat,
      storedSeat: await storedSeatId(seat, env),
      tag: defaultTag,
      ticketTag,
      ticketIssued,
      clientMinIssued,
    });
    if (res.cacheNegative) {
      rememberNegativeKey(keyHash);
    }
    const extra = res.retryAfter ? { "Retry-After": String(res.retryAfter) } : {};
    return jsonResponse(res.body, res.status, extra);
  },
};
