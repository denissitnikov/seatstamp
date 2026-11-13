import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

// Register a minimal `cloudflare:workers` shim so `SeatCoordinator extends DurableObject` imports directly in Node
const shimURL =
  "data:text/javascript,export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }";
if (typeof nodeModule.registerHooks === "function") {
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "cloudflare:workers") {
        return { shortCircuit: true, url: shimURL };
      }
      return nextResolve(specifier, context);
    },
  });
} else {
  const loaderSource = `
export async function resolve(specifier, context, nextResolve) {
  if (specifier === "cloudflare:workers") {
    return { shortCircuit: true, url: ${JSON.stringify(shimURL)} };
  }
  return nextResolve(specifier, context);
}
`;
  nodeModule.register(`data:text/javascript,${encodeURIComponent(loaderSource)}`);
}

const { default: worker, SeatCoordinator, classifyKeyFormat, verifySeatTicket, deriveOrderTag, __resetIsolateStateForTests, __exhaustStoreBudgetForTests } = await import("./worker.js");

// Every test starts from a cold isolate: no shared rate-limit windows, no negative or recent-valid cache bleed.
test.beforeEach(() => __resetIsolateStateForTests({ ENVIRONMENT: "test" }));

async function generateEd25519KeyPairB64() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const privB64 = Buffer.from(pkcs8).toString("base64");
  return { privB64, publicKey: kp.publicKey, rawPub };
}

function createSQLiteDOHarness(envFactory) {
  const instances = new Map();
  return {
    idFromName(name) {
      return name;
    },
    get(id) {
      if (!instances.has(id)) {
        let db = new DatabaseSync(":memory:");
        let scheduledAlarmMs = null;
        const sqlWrapper = {
          exec(query, ...params) {
            const stmt = db.prepare(query);
            if (/^\s*(SELECT|PRAGMA)\b/i.test(query)) {
              const rows = stmt.all(...params);
              return {
                toArray: () => rows,
                [Symbol.iterator]: () => rows[Symbol.iterator](),
              };
            }
            stmt.run(...params);
            return { toArray: () => [] };
          },
        };
        const ctx = {
          storage: {
            sql: sqlWrapper,
            transactionSync(fn) {
              db.exec("BEGIN IMMEDIATE");
              try {
                const out = fn();
                db.exec("COMMIT");
                return out;
              } catch (err) {
                db.exec("ROLLBACK");
                throw err;
              }
            },
            async setAlarm(ms) {
              scheduledAlarmMs = Number(ms);
              ctx.__alarmCalls += 1;
            },
            async getAlarm() {
              return scheduledAlarmMs;
            },
            async deleteAll() {
              db.close();
              db = new DatabaseSync(":memory:");
              scheduledAlarmMs = null;
            },
          },
        };
        ctx.__alarmCalls = 0;
        instances.set(id, new SeatCoordinator(ctx, envFactory()));
      }
      return instances.get(id);
    },
  };
}

function makeActivateRequest(key, seat, ip = "203.0.113.10") {
  return new Request("https://activate.example.com/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": ip,
    },
    body: JSON.stringify({ action: "activate", key, seat }),
  });
}

async function sha256HexTest(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("1. Valid paid Stripe Checkout Session mints verifiable Ed25519 LK1- ticket and enforces 2-Mac seat cap", async () => {
  const { privB64, publicKey } = await generateEd25519KeyPairB64();
  const sessionKey = "cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    TICKET_SCHEME: "MYAPP-V1",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    STRIPE_ALLOWED_PAYMENT_LINKS: "plink_usd_example,plink_cny_example",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      assert.ok(String(url).includes("expand[]=payment_intent.latest_charge"));
      return new Response(
        JSON.stringify({
          id: sessionKey,
          object: "checkout.session",
          livemode: true,
          mode: "payment",
          payment_link: "plink_cny_example",
          status: "complete",
          payment_status: "paid",
          amount_total: 5800,
          payment_intent: {
            id: "pi_123",
            status: "succeeded",
            amount: 5800,
            amount_received: 5800,
            latest_charge: {
              id: "ch_123",
              amount: 5800,
              amount_refunded: 0,
              refunded: false,
              disputed: false,
            },
          },
        }),
        { status: 200 }
      );
    },
  };

  // Mac #1 activates
  const res1 = await worker.fetch(makeActivateRequest(sessionKey, "1111222233334444"), env);
  assert.equal(res1.status, 200);
  const body1 = await res1.json();
  assert.equal(body1.seatsUsed, 1);
  assert.equal(body1.maxSeats, 2);
  assert.match(body1.ticket, /^LK1-[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  const [payloadB64, sigB64] = body1.ticket.slice(4).split(".");
  const payloadBytes = Buffer.from(payloadB64, "base64url");
  const sigBytes = Buffer.from(sigB64, "base64url");
  const sigOk = await crypto.subtle.verify("Ed25519", publicKey, sigBytes, payloadBytes);
  assert.equal(sigOk, true);
  assert.match(payloadBytes.toString("utf8"), /^MYAPP-V1\|ORD-[0-9A-F]{16}\|\d+\|1111222233334444$/);

  // Mac #2 activates
  const res2 = await worker.fetch(makeActivateRequest(sessionKey, "5555666677778888"), env);
  assert.equal(res2.status, 200);
  const body2 = await res2.json();
  assert.equal(body2.seatsUsed, 2);

  // Mac #3 rejected with 409 seat_limit_reached
  const res3 = await worker.fetch(makeActivateRequest(sessionKey, "9999aaaabbbbcccc"), env);
  assert.equal(res3.status, 409);
  const body3 = await res3.json();
  assert.equal(body3.error, "seat_limit_reached");
});

test("2. Refunded and disputed Stripe Checkout Sessions are rejected (403)", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const refundedKey = "cs_live_refundedSessionKey000000000000001";
  const disputedKey = "cs_live_disputedSessionKey000000000000002";

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      if (String(url).startsWith("https://api.stripe.com/v1/disputes?")) {
        return new Response(JSON.stringify({ object: "list", data: [{ id: "dp_1", status: "lost" }], has_more: false }), { status: 200 });
      }
      const isRefunded = String(url).includes(refundedKey);
      return new Response(
        JSON.stringify({
          object: "checkout.session",
          livemode: true,
          mode: "payment",
          status: "complete",
          payment_status: "paid",
          amount_total: 900,
          payment_intent: {
            id: "pi_ref",
            status: "succeeded",
            amount: 900,
            amount_received: 900,
            latest_charge: {
              id: "ch_ref",
              amount: 900,
              amount_refunded: isRefunded ? 900 : 0,
              refunded: isRefunded,
              disputed: !isRefunded,
            },
          },
        }),
        { status: 200 }
      );
    },
  };

  const rRef = await worker.fetch(makeActivateRequest(refundedKey, "1111222233334444", "198.51.100.2"), env);
  assert.equal(rRef.status, 403);

  const rDisp = await worker.fetch(makeActivateRequest(disputedKey, "1111222233334444", "198.51.100.3"), env);
  assert.equal(rDisp.status, 403);
});

test("3. Restricted Stripe key returning 403 or missing latest_charge fails closed (502) instead of bypassing refund checks", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key403 = "cs_live_restrictedKeyExpand403Session0003";
  const keyNoCharge = "cs_live_missingLatestChargeOnPaidSess0003";
  let fetchCount = 0;

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "rk_live_missing_charges_read",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      fetchCount += 1;
      if (String(url).includes(keyNoCharge)) {
        return new Response(
          JSON.stringify({
            object: "checkout.session",
            livemode: true,
            mode: "payment",
            status: "complete",
            payment_status: "paid",
            amount_total: 900,
            payment_intent: { status: "succeeded", amount: 900, amount_received: 900, latest_charge: null },
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ error: { message: "Insufficient permissions" } }), { status: 403 });
    },
  };

  const res = await worker.fetch(makeActivateRequest(key403, "aaaa222233334444", "198.51.100.4"), env);
  assert.equal(res.status, 502);
  assert.equal(fetchCount, 1);

  const resNoCharge = await worker.fetch(makeActivateRequest(keyNoCharge, "aaaa222233334444", "198.51.100.4"), env);
  assert.equal(resNoCharge.status, 502);
});

test("4. Subscription sessions and non-allowlisted Payment Links are rejected (403)", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const subKey = "cs_live_subscriptionModeSession0000000004";
  const wrongLinkKey = "cs_live_wrongPaymentLinkSession0000000005";

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    STRIPE_ALLOWED_PAYMENT_LINKS: "plink_myapp_usd",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      const isSub = String(url).includes(subKey);
      return new Response(
        JSON.stringify({
          object: "checkout.session",
          livemode: true,
          mode: isSub ? "subscription" : "payment",
          payment_link: isSub ? "plink_myapp_usd" : "plink_other_saas",
          status: "complete",
          payment_status: "paid",
          amount_total: 900,
          payment_intent: {
            status: "succeeded",
            amount: 900,
            amount_received: 900,
            latest_charge: { amount: 900, amount_refunded: 0, refunded: false, disputed: false },
          },
        }),
        { status: 200 }
      );
    },
  };

  const rSub = await worker.fetch(makeActivateRequest(subKey, "bbbb222233334444", "198.51.100.5"), env);
  assert.equal(rSub.status, 403);

  const rWrongLink = await worker.fetch(makeActivateRequest(wrongLinkKey, "bbbb222233334444", "198.51.100.6"), env);
  assert.equal(rWrongLink.status, 403);
});

test("5. GET /thank-you returns 503 when Stripe is unreachable and 200 with localStorage backup & URL intact when verified", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const transientKey = "cs_live_thankYouTransientTimeout000000006";
  const goodKey = "cs_live_thankYouVerifiedSuccess0000000007";

  const envTimeout = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    __TEST_FETCH: async () => new Response("Bad Gateway", { status: 502 }),
  };
  const r503 = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${transientKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.7" },
    }),
    envTimeout
  );
  assert.equal(r503.status, 503);

  const envGood = {
    ENVIRONMENT: "test",
    APP_NAME: "PixelTool",
    APP_URL_SCHEME: "pixeltool",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    __TEST_FETCH: async () =>
      new Response(
        JSON.stringify({
          object: "checkout.session",
          livemode: true,
          mode: "payment",
          status: "complete",
          payment_status: "paid",
          amount_total: 900,
          payment_intent: {
            status: "succeeded",
            amount: 900,
            amount_received: 900,
            latest_charge: { amount: 900, amount_refunded: 0, refunded: false, disputed: false },
          },
        }),
        { status: 200 }
      ),
  };
  const r200 = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${goodKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.8" },
    }),
    envGood
  );
  assert.equal(r200.status, 200);
  const html = await r200.text();
  assert.match(html, /PixelTool/);
  assert.match(html, /pixeltool:\/\/activate\?key=/);
  assert.match(html, /localStorage\.setItem/);
  assert.doesNotMatch(html, /history\.replaceState/);
});

const PAID_SESSION_JSON = {
  object: "checkout.session",
  livemode: true,
  mode: "payment",
  status: "complete",
  payment_status: "paid",
  amount_total: 900,
  payment_intent: {
    status: "succeeded",
    amount: 900,
    amount_received: 900,
    latest_charge: { amount: 900, amount_refunded: 0, refunded: false, disputed: false },
  },
};

function paidStripeFetch() {
  return async () => new Response(JSON.stringify(PAID_SESSION_JSON), { status: 200 });
}

function makePaidEnv(privB64, extra = {}) {
  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: paidStripeFetch(),
    ...extra,
  };
  return env;
}

test("6a. Missing SEAT_DO binding -> 500 storage_unconfigured", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    __TEST_FETCH: async () => new Response(JSON.stringify(PAID_SESSION_JSON), { status: 200 }),
  };
  const res = await worker.fetch(makeActivateRequest("cs_live_noDurableObjectBinding00000000006", "9999aaaabbbbcccc", "198.51.100.9"), env);
  assert.equal(res.status, 500);
  assert.deepEqual(await res.json(), { error: "storage_unconfigured" });
});

test("6c. Refunded key with an existing DO record wipes the DO completely (0 bytes) and negative-caches the key", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_refundAfterActivationWipesDO00006";
  let refunded = false;
  let stripeCalls = 0;

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async () => {
      stripeCalls += 1;
      const json = structuredClone(PAID_SESSION_JSON);
      if (refunded) {
        json.payment_intent.latest_charge.refunded = true;
        json.payment_intent.latest_charge.amount_refunded = 900;
      }
      return new Response(JSON.stringify(json), { status: 200 });
    },
  };

  const r1 = await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.12"), env);
  assert.equal(r1.status, 200);
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  assert.equal(stub._hasSchema(), true);

  refunded = true;
  const r2 = await worker.fetch(makeActivateRequest(key, "5555666677778888", "198.51.100.12"), env);
  assert.equal(r2.status, 403);
  assert.deepEqual(await r2.json(), { error: "invalid_key" });
  assert.equal(stub._hasSchema(), false);

  const before = stripeCalls;
  const r3 = await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.12"), env);
  assert.equal(r3.status, 403);
  assert.equal(stripeCalls, before);
});

test("6d. classifyKeyFormat edge cases", () => {
  const live = { STRIPE_SECRET_KEY: "sk_live_x" };
  const testEnv = { STRIPE_SECRET_KEY: "sk_test_x" };
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  const cs = "cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

  assert.equal(classifyKeyFormat(null, live), "invalid");
  assert.equal(classifyKeyFormat(undefined, live), "invalid");
  assert.equal(classifyKeyFormat(12345, live), "invalid");
  assert.equal(classifyKeyFormat("", live), "invalid");
  assert.equal(classifyKeyFormat("cs_live_short", live), "invalid");
  assert.equal(classifyKeyFormat("cs_live_" + "a".repeat(249), live), "invalid");
  assert.equal(classifyKeyFormat("cs_live_" + "a".repeat(140), live), "stripe");
  assert.equal(classifyKeyFormat("cs_live_" + "a".repeat(141), live), "invalid");
  assert.equal(classifyKeyFormat("cs_live_" + "a".repeat(23), live), "invalid");
  assert.equal(classifyKeyFormat("cs_live_" + "a".repeat(24), live), "stripe");

  assert.equal(classifyKeyFormat("LK1-abcdefghijklmnop.sig", live), "invalid");
  assert.equal(classifyKeyFormat("lk1-abcdefghijklmnop.sig", live), "invalid");
  assert.equal(classifyKeyFormat("APP1-abcdefghijklmnop.sig", { ...live, TICKET_PREFIX: "APP1-" }), "invalid");

  assert.equal(classifyKeyFormat(`  ${cs}\n`, live), "stripe");

  assert.equal(classifyKeyFormat(cs, {}), "invalid");
  assert.equal(classifyKeyFormat(cs, live), "stripe");
  assert.equal(classifyKeyFormat(cs, { STRIPE_SECRET_KEY: "rk_live_x" }), "stripe");
  assert.equal(classifyKeyFormat(cs.replace("cs_live_", "cs_test_"), live), "invalid");
  assert.equal(classifyKeyFormat(cs.replace("cs_live_", "cs_test_"), testEnv), "stripe");
  assert.equal(classifyKeyFormat(cs, testEnv), "stripe");
  assert.equal(classifyKeyFormat(cs + "-", live), "invalid");
  assert.equal(classifyKeyFormat("cs_prod_" + "a".repeat(30), live), "invalid");

  assert.equal(classifyKeyFormat(uuid, live), "invalid");
  assert.equal(classifyKeyFormat("MYAPP-" + uuid, live), "invalid");
});

function makePostRequest(bodyObj, ip = "203.0.113.50", headers = {}) {
  return new Request("https://activate.example.com/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip, ...headers },
    body: typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj),
  });
}

function makeDeactivateRequest(key, seat, ticket, ip = "203.0.113.51") {
  const body = { action: "deactivate", key, seat };
  if (ticket !== undefined) body.ticket = ticket;
  return makePostRequest(body, ip);
}

async function activateAndGetTicket(env, key, seat, ip) {
  const res = await worker.fetch(makeActivateRequest(key, seat, ip), env);
  assert.equal(res.status, 200, `activate ${seat} expected 200, got ${res.status}`);
  return res.json();
}

test("7. Ticket-authenticated deactivate soft-releases the seat, returns revokedBefore, and frees the cap for a new Mac", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_ticketDeactivateHappyPath000000010";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.10";

  const a1 = await activateAndGetTicket(env, key, "1111222233334444", ip);
  assert.equal(a1.revokedBefore, 0);
  const a2 = await activateAndGetTicket(env, key, "5555666677778888", ip);
  assert.equal(a2.seatsUsed, 2);

  const full = await worker.fetch(makeActivateRequest(key, "9999aaaabbbbcccc", ip), env);
  assert.equal(full.status, 409);

  const d = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", a1.ticket, ip), env);
  assert.equal(d.status, 200);
  const dBody = await d.json();
  assert.equal(dBody.ok, true);
  assert.ok(Number.isInteger(dBody.revokedBefore) && dBody.revokedBefore > 0);

  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const rows = stub.sql.exec(`SELECT seat, deactivated_at FROM seats ORDER BY seat`).toArray();
  assert.equal(rows.length, 2);
  const released = rows.find((r) => r.seat === "1111222233334444");
  assert.ok(released && Number(released.deactivated_at) > 0);

  const a3 = await activateAndGetTicket(env, key, "9999aaaabbbbcccc", ip);
  assert.equal(a3.seatsUsed, 2);
  assert.equal(a3.revokedBefore, dBody.revokedBefore);
  const issued3 = Number(Buffer.from(a3.ticket.slice(4).split(".")[0], "base64url").toString("utf8").split("|")[2]);
  assert.ok(issued3 > a3.revokedBefore);

  const d3 = await worker.fetch(makeDeactivateRequest(key, "9999aaaabbbbcccc", a3.ticket, ip), env);
  assert.equal(d3.status, 200);
  const a1Again = await activateAndGetTicket(env, key, "1111222233334444", ip);
  assert.equal(a1Again.seatsUsed, 2);
  const row1 = stub.sql.exec(`SELECT deactivated_at FROM seats WHERE seat = '1111222233334444'`).toArray();
  assert.equal(row1[0].deactivated_at, null);
});

test("8. Deactivate with a ticket for a different seat -> 403 invalid_ticket and seat remains active", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_ticketWrongSeatDeactivate000000011";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.11";

  const a1 = await activateAndGetTicket(env, key, "1111222233334444", ip);
  await activateAndGetTicket(env, key, "5555666677778888", ip);

  const d = await worker.fetch(makeDeactivateRequest(key, "5555666677778888", a1.ticket, ip), env);
  assert.equal(d.status, 403);
  assert.equal((await d.json()).error, "invalid_ticket");

  const [p, s] = a1.ticket.slice(4).split(".");
  const flipped = s.slice(0, -2) + (s.endsWith("AA") ? "BB" : "AA");
  const dBad = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", `LK1-${p}.${flipped}`, ip), env);
  assert.equal(dBad.status, 403);

  const other = await generateEd25519KeyPairB64();
  const otherPriv = await crypto.subtle.importKey("pkcs8", Buffer.from(other.privB64, "base64"), { name: "Ed25519" }, false, ["sign"]);
  const payload = Buffer.from(p, "base64url");
  const forgedSig = Buffer.from(await crypto.subtle.sign("Ed25519", otherPriv, payload)).toString("base64url");
  const dForged = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", `LK1-${p}.${forgedSig}`, ip), env);
  assert.equal(dForged.status, 403);

  const full = await worker.fetch(makeActivateRequest(key, "9999aaaabbbbcccc", ip), env);
  assert.equal(full.status, 409);
});

test("9. Deactivate without ticket -> 400 ticket_required and the seat stays claimed", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_deactivateNeedsTicket0000000000012";
  const ip = "198.51.100.12";

  const env = makePaidEnv(privB64);
  await activateAndGetTicket(env, key, "1111222233334444", ip);
  const d = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", undefined, ip), env);
  assert.equal(d.status, 400);
  assert.equal((await d.json()).error, "ticket_required");
  const again = await activateAndGetTicket(env, key, "1111222233334444", ip);
  assert.equal(again.seatsUsed, 1);
});
test("10. Deactivate for an unknown (never activated) key -> 404 unknown_key; format-invalid key returns 403", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_neverActivatedUnknownKey0000000013";
  const ip = "198.51.100.13";
  // A genuine ticket, but this Worker's storage has never seen the key.
  const issued = await activateAndGetTicket(makePaidEnv(privB64), key, "1111222233334444", ip);
  const env = makePaidEnv(privB64);

  const d = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", issued.ticket, ip), env);
  assert.equal(d.status, 404);
  assert.equal((await d.json()).error, "unknown_key");

  const dInvalid = await worker.fetch(makeDeactivateRequest("not-a-real-key-format-xyz", "1111222233334444", issued.ticket, ip), env);
  assert.equal(dInvalid.status, 403);
  assert.equal((await dInvalid.json()).error, "invalid_key");
});

test("11. revokedBefore is returned on every activate/deactivate response and is monotonic", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_revokedBeforeMonotonic00000000014";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.14";

  const seen = [];
  const a1 = await activateAndGetTicket(env, key, "1111222233334444", ip);
  seen.push(a1.revokedBefore);
  const a2 = await activateAndGetTicket(env, key, "5555666677778888", ip);
  seen.push(a2.revokedBefore);

  const d1 = await (await worker.fetch(makeDeactivateRequest(key, "1111222233334444", a1.ticket, ip), env)).json();
  seen.push(d1.revokedBefore);

  const a1b = await activateAndGetTicket(env, key, "1111222233334444", ip);
  seen.push(a1b.revokedBefore);

  const d2 = await (await worker.fetch(makeDeactivateRequest(key, "5555666677778888", a2.ticket, ip), env)).json();
  seen.push(d2.revokedBefore);
  const d2again = await (await worker.fetch(makeDeactivateRequest(key, "5555666677778888", a2.ticket, ip), env)).json();
  seen.push(d2again.revokedBefore);

  for (const v of seen) assert.ok(Number.isInteger(v));
  for (let i = 1; i < seen.length; i++) {
    assert.ok(seen[i] >= seen[i - 1]);
  }
  assert.ok(seen[seen.length - 1] > 0);
});

test("12. POST with an Origin header or Sec-Fetch-Site: cross-site is rejected with 403 forbidden_origin", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = makePaidEnv(privB64);
  const body = { action: "activate", key: "cs_live_originRejectedBrowserPost000000015", seat: "1111222233334444" };

  const r1 = await worker.fetch(makePostRequest(body, "198.51.100.15", { Origin: "https://evil.example" }), env);
  assert.equal(r1.status, 403);
  assert.equal((await r1.json()).error, "forbidden_origin");

  const r2 = await worker.fetch(makePostRequest(body, "198.51.100.15", { "Sec-Fetch-Site": "cross-site" }), env);
  assert.equal(r2.status, 403);
});

test("13. Oversize body -> 413 payload_too_large via bounded stream reader (no Content-Length / chunked)", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = makePaidEnv(privB64);
  let fetchCalls = 0;
  env.__TEST_FETCH = async () => {
    fetchCalls += 1;
    return paidStripeFetch()();
  };

  const declared = new Request("https://activate.example.com/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.16", "Content-Length": "999999" },
    body: "{}",
  });
  const r1 = await worker.fetch(declared, env);
  assert.equal(r1.status, 413);

  const filler = "x".repeat(6144);
  const big = `{"action":"activate","key":"cs_live_oversizeBodyStreamed0000000000016","seat":"1111222233334444","pad":"${filler}"}`;
  const enc = new TextEncoder();
  let offset = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (offset >= big.length) return controller.close();
      controller.enqueue(enc.encode(big.slice(offset, offset + 512)));
      offset += 512;
    },
  });
  const streamed = new Request("https://activate.example.com/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.16" },
    body: stream,
    duplex: "half",
  });
  const r2 = await worker.fetch(streamed, env);
  assert.equal(r2.status, 413);
  assert.equal((await r2.json()).error, "payload_too_large");
  assert.ok(offset < big.length);
  assert.equal(fetchCalls, 0);

  const ok = await worker.fetch(makeActivateRequest("cs_live_oversizeBodyStreamed0000000000016", "1111222233334444", "198.51.100.16"), env);
  assert.equal(ok.status, 200);
});

test("14. env.__TEST_FETCH is ignored unless env.ENVIRONMENT === 'test'", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_testFetchHookGatedByEnv00000000017";
  let hookCalls = 0;
  let globalCalls = 0;

  const env = makePaidEnv(privB64);
  delete env.ENVIRONMENT;
  env.__TEST_FETCH = async () => {
    hookCalls += 1;
    return paidStripeFetch()();
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    globalCalls += 1;
    return new Response("Service Unavailable", { status: 503 });
  };
  try {
    const res = await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.17"), env);
    assert.equal(res.status, 502);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(hookCalls, 0);
  assert.equal(globalCalls, 1);

  const envProd = makePaidEnv(privB64, { ENVIRONMENT: "production" });
  envProd.__TEST_FETCH = async () => {
    hookCalls += 1;
    return paidStripeFetch()();
  };
  globalThis.fetch = async () => {
    globalCalls += 1;
    return new Response("Service Unavailable", { status: 503 });
  };
  try {
    const res = await worker.fetch(makeActivateRequest(key, "5555666677778888", "198.51.100.18"), envProd);
    assert.equal(res.status, 502);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(hookCalls, 0);
  assert.equal(globalCalls, 2);
});

test("15. GET /thank-you is rate limited to 3 requests/min/IP independently of the activation budget", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_thankYouRateLimitOracle00000000018";
  const ip = "198.51.100.19";
  const env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    __TEST_FETCH: paidStripeFetch(),
  };
  const mk = () => new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": ip } });

  for (let i = 0; i < 3; i++) {
    const r = await worker.fetch(mk(), env);
    assert.equal(r.status, 200);
  }
  const r4 = await worker.fetch(mk(), env);
  assert.equal(r4.status, 429);
  assert.equal(r4.headers.get("Retry-After"), "60");

  const envDO = makePaidEnv(privB64);
  const act = await worker.fetch(makeActivateRequest(key, "1111222233334444", ip), envDO);
  assert.equal(act.status, 200);
});

test("16. /thank-you page has no inline event handlers and a nonce-based CSP without 'unsafe-inline' for scripts", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_thankYouCspNonceNoInline0000000019";
  const env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    __TEST_FETCH: paidStripeFetch(),
  };
  const r = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": "198.51.100.20" } }),
    env
  );
  assert.equal(r.status, 200);
  const html = await r.text();
  const csp = r.headers.get("Content-Security-Policy") || "";
  const m = /script-src 'nonce-([A-Za-z0-9_-]+)'/.exec(csp);
  assert.ok(m);
  assert.doesNotMatch(csp, /script-src[^;]*'unsafe-inline'/);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
  assert.ok(html.includes(`<script nonce="${m[1]}">`));
  assert.match(html, /addEventListener\("click"/);

  const r2 = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": "198.51.100.21" } }),
    env
  );
  const m2 = /script-src 'nonce-([A-Za-z0-9_-]+)'/.exec(r2.headers.get("Content-Security-Policy") || "");
  assert.ok(m2 && m2[1] !== m[1]);
});

test("17. v1 SQLite schema (no deactivated_at) is migrated in place via PRAGMA-guarded ALTER TABLE and keeps existing seats", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_schemaMigrationFromV1000000000020";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.22";

  const keyHash = await sha256HexTest("seatstamp-key-v1|" + key);
  const stub = env.SEAT_DO.get("lic:" + keyHash);

  stub.sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  stub.sql.exec(`CREATE TABLE IF NOT EXISTS seats (seat TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`);
  stub.sql.exec(`INSERT INTO meta (key, value) VALUES ('tag', 'OLDTAG01')`);
  stub.sql.exec(`INSERT INTO meta (key, value) VALUES ('verified_at', ?)`, String(Date.now()));
  stub.sql.exec(`INSERT INTO seats (seat, created_at) VALUES ('1111222233334444', ?)`, Date.now());
  stub.sql.exec(`INSERT INTO seats (seat, created_at) VALUES ('5555666677778888', ?)`, Date.now());

  const full = await worker.fetch(makeActivateRequest(key, "9999aaaabbbbcccc", ip), env);
  assert.equal(full.status, 409);
  const cols = stub.sql.exec(`PRAGMA table_info(seats)`).toArray().map((r) => r.name);
  assert.ok(cols.includes("deactivated_at"));
  assert.ok(cols.includes("last_seen_at"));

  const a = await activateAndGetTicket(env, key, "1111222233334444", ip);
  assert.match(Buffer.from(a.ticket.slice(4).split(".")[0], "base64url").toString("utf8"), /\|ORD-OLDTAG01\|/);

  const d = await worker.fetch(makeDeactivateRequest(key, "1111222233334444", a.ticket, ip), env);
  assert.equal(d.status, 200);
  const a3 = await activateAndGetTicket(env, key, "9999aaaabbbbcccc", ip);
  assert.equal(a3.seatsUsed, 2);
});

test("18. Cross-language golden-vectors.json (Swift CryptoKit <-> Worker WebCrypto) verifies identically", async () => {
  const vectors = JSON.parse(readFileSync(new URL("../fixtures/golden-vectors.json", import.meta.url), "utf8"));
  const env = {
    TICKET_SCHEME: vectors.ticket.scheme,
    TICKET_PREFIX: vectors.ticket.prefix,
    ED25519_PKCS8_B64: vectors.licenseTestKey.pkcs8Base64,
    ED25519_PUB_B64: vectors.licenseTestKey.publicKeyBase64,
  };

  const res = await verifySeatTicket(vectors.ticket.encoded, vectors.ticket.seat, env);
  assert.deepEqual(res, {
    ok: true,
    tag: vectors.ticket.tag.slice(4),
    issued: vectors.ticket.issued,
    seat: vectors.ticket.seat,
  });

  assert.equal((await verifySeatTicket(vectors.ticket.encoded, vectors.ticket.seat, { ...env, TICKET_SCHEME: "OTHER-V1" })).ok, false);
  assert.equal((await verifySeatTicket(vectors.ticket.encoded, "0000000000000000", env)).ok, false);

  const updPubRaw = Buffer.from(vectors.updateTestKey.publicKeyBase64, "base64");
  const updPub = await crypto.subtle.importKey("raw", updPubRaw, { name: "Ed25519" }, false, ["verify"]);
  const sigBytes = Buffer.from(vectors.manifest.signatureBase64URL, "base64url");
  const canonBytes = Buffer.from(vectors.manifest.canonicalUTF8, "utf8");
  assert.equal(await crypto.subtle.verify("Ed25519", updPub, sigBytes, canonBytes), true);

  // Manifest with revoked_tags vector verifies identically under WebCrypto
  const revSigBytes = Buffer.from(vectors.manifestWithRevokedTags.signatureBase64URL, "base64url");
  const revCanonBytes = Buffer.from(vectors.manifestWithRevokedTags.canonicalUTF8, "utf8");
  assert.equal(await crypto.subtle.verify("Ed25519", updPub, revSigBytes, revCanonBytes), true);

  // Manifest with a signed artifact sha256 and size verifies identically under WebCrypto
  const artSigBytes = Buffer.from(vectors.manifestWithArtifact.signatureBase64URL, "base64url");
  const artCanonBytes = Buffer.from(vectors.manifestWithArtifact.canonicalUTF8, "utf8");
  assert.equal(await crypto.subtle.verify("Ed25519", updPub, artSigBytes, artCanonBytes), true);

  // Manifest with a signed manifest_seq verifies identically under WebCrypto
  const seqSigBytes = Buffer.from(vectors.manifestWithSequence.signatureBase64URL, "base64url");
  const seqCanonBytes = Buffer.from(vectors.manifestWithSequence.canonicalUTF8, "utf8");
  assert.equal(await crypto.subtle.verify("Ed25519", updPub, seqSigBytes, seqCanonBytes), true);

  // Cross-language orderTagDerivation vector (16-hex ORD- tag from domain + purchaseKey)
  const otd = vectors.orderTagDerivation;
  const computedHash = await sha256HexTest(otd.domain + otd.purchaseKey);
  assert.equal(computedHash, otd.expectedKeyHash);
  const derivedTag = await deriveOrderTag(`  ${otd.purchaseKey}\n`, { KEY_HASH_DOMAIN: otd.domain });
  assert.equal(derivedTag, otd.expectedOrderTag);
  assert.match(derivedTag, /^ORD-[0-9A-F]{16}$/);
});

test("19. Optional EVICT_OLDEST_SEAT_AFTER_DAYS evicts a stale seat when a 3rd Mac activates after the cooldown", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_evictOldestSeatCooldown0000000021";
  const env = makePaidEnv(privB64, { EVICT_OLDEST_SEAT_AFTER_DAYS: "30" });
  const ip = "198.51.100.23";

  await activateAndGetTicket(env, key, "1111222233334444", ip);
  await activateAndGetTicket(env, key, "5555666677778888", ip);

  // While both seats are recent (<30 days), Mac #3 is still rejected with 409
  const blocked = await worker.fetch(makeActivateRequest(key, "9999aaaabbbbcccc", ip), env);
  assert.equal(blocked.status, 409);

  // Backdate seat #1 to 35 days ago -> Mac #3 now evicts seat #1 and claims Seat 2/2
  const keyHash = await sha256HexTest("seatstamp-key-v1|" + key);
  const stub = env.SEAT_DO.get("lic:" + keyHash);
  stub.sql.exec(`UPDATE seats SET created_at = ? WHERE seat = '1111222233334444'`, Date.now() - 35 * 86_400_000);

  const a3 = await activateAndGetTicket(env, key, "9999aaaabbbbcccc", ip);
  assert.equal(a3.seatsUsed, 2);
  assert.ok(a3.revokedBefore > 0);
  const activeSeats = stub.sql.exec(`SELECT seat FROM seats WHERE deactivated_at IS NULL ORDER BY seat`).toArray().map((r) => r.seat);
  assert.deepEqual(activeSeats, ["5555666677778888", "9999aaaabbbbcccc"]);

  const backdateActiveSeats = () => {
    const old = Date.now() - 35 * 86_400_000;
    stub.sql.exec(`UPDATE seats SET created_at = ? WHERE deactivated_at IS NULL`, old);
    stub.sql.exec(`UPDATE seats SET last_seen_at = ? WHERE deactivated_at IS NULL AND last_seen_at IS NOT NULL`, old);
  };
  const setLastEvicted = (sec) =>
    stub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('last_evicted_at', ?)`, String(sec));

  // All remaining seats are stale, but the last eviction was moments ago: the cooldown refuses a second one.
  backdateActiveSeats();
  const cooldown = await worker.fetch(makeActivateRequest(key, "ddddeeeeffff0000", ip), env);
  assert.equal(cooldown.status, 409);

  // Cooldown elapsed: a second eviction is allowed (release 2 of the default budget of 2).
  setLastEvicted(Math.floor(Date.now() / 1000) - 31 * 86_400);
  const a4 = await activateAndGetTicket(env, key, "ddddeeeeffff0000", ip);
  assert.equal(a4.seatsUsed, 2);

  // Cooldown elapsed again, but the yearly release budget is used up.
  backdateActiveSeats();
  setLastEvicted(Math.floor(Date.now() / 1000) - 31 * 86_400);
  const overBudget = await worker.fetch(makeActivateRequest(key, "0123456789abcdef", ip), env);
  assert.equal(overBudget.status, 409);
});

test("19b. eviction uses last_seen_at and never rewrites created_at", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const ip = "198.51.100.24";
  const X = "1111222233334444";
  const Y = "5555666677778888";
  const Z = "9999aaaabbbbcccc";

  // (a) + (b)
  const keyEvict = "cs_live_evictUsesLastSeenAt000000000000022";
  const envEvict = makePaidEnv(privB64, { EVICT_OLDEST_SEAT_AFTER_DAYS: "30" });
  await activateAndGetTicket(envEvict, keyEvict, X, ip);
  await activateAndGetTicket(envEvict, keyEvict, Y, ip);
  const stubEvict = envEvict.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + keyEvict)));
  const old = Date.now() - 35 * 86_400_000;
  stubEvict.sql.exec(`UPDATE seats SET created_at = ?`, old);
  const createdBefore = stubEvict.sql.exec(`SELECT created_at FROM seats WHERE seat = ?`, X).toArray()[0].created_at;

  await activateAndGetTicket(envEvict, keyEvict, X, ip);
  const xRow = stubEvict.sql.exec(`SELECT created_at, last_seen_at FROM seats WHERE seat = ?`, X).toArray()[0];
  assert.equal(xRow.created_at, createdBefore);
  assert.ok(Number(xRow.last_seen_at) > old);

  await activateAndGetTicket(envEvict, keyEvict, Z, ip);
  const active = stubEvict.sql
    .exec(`SELECT seat FROM seats WHERE deactivated_at IS NULL ORDER BY seat`)
    .toArray()
    .map((r) => r.seat);
  assert.deepEqual(active, [X, Z]);

  // (c)
  const keyPlain = "cs_live_reactivateKeepsCreatedAt0000000023";
  const envPlain = makePaidEnv(privB64);
  const a1 = await activateAndGetTicket(envPlain, keyPlain, X, ip);
  await activateAndGetTicket(envPlain, keyPlain, Y, ip);
  const stubPlain = envPlain.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + keyPlain)));
  const before = stubPlain.sql.exec(`SELECT created_at, last_seen_at FROM seats WHERE seat = ?`, X).toArray()[0];
  assert.equal(before.last_seen_at, null);
  const d = await worker.fetch(makeDeactivateRequest(keyPlain, X, a1.ticket, ip), envPlain);
  assert.equal(d.status, 200);
  await activateAndGetTicket(envPlain, keyPlain, X, ip);
  const after = stubPlain.sql.exec(`SELECT created_at, last_seen_at, deactivated_at FROM seats WHERE seat = ?`, X).toArray()[0];
  assert.equal(after.created_at, before.created_at);
  assert.equal(after.deactivated_at, null);
  assert.ok(Number(after.last_seen_at) > 0);
});

test("20. /thank-you embeds sessionId within the 1-hour checkout window and renders the localStorage-only shell when expired or when all seats are claimed", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const freshKey = "cs_live_thankYouWindowFreshSession0000022";
  const oldKey = "cs_live_thankYouWindowExpiredSession00023";
  const nowSec = Math.floor(Date.now() / 1000);

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    APP_NAME: "SampleApp",
    APP_URL_SCHEME: "sampleapp",
    THANK_YOU_WINDOW_SECONDS: "3600",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      const isOld = String(url).includes(oldKey);
      const created = isOld ? nowSec - 7200 : nowSec - 60;
      return new Response(
        JSON.stringify({
          ...PAID_SESSION_JSON,
          created,
          payment_intent: {
            ...PAID_SESSION_JSON.payment_intent,
            created,
            latest_charge: {
              ...PAID_SESSION_JSON.payment_intent.latest_charge,
              created,
            },
          },
        }),
        { status: 200 }
      );
    },
  };

  // 1) Fresh session (<1 hour old, 0/2 seats) embeds the key in HTML
  const rFresh = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${freshKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.24" },
    }),
    env
  );
  assert.equal(rFresh.status, 200);
  const htmlFresh = await rFresh.text();
  assert.ok(htmlFresh.includes(freshKey));

  // 2) After 1 seat is claimed (<2 seats), /thank-you within 1 hour still shows the key so the buyer can save .txt
  await activateAndGetTicket(env, freshKey, "1111222233334444", "198.51.100.24");
  const rOneSeat = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${freshKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.24" },
    }),
    env
  );
  assert.ok((await rOneSeat.text()).includes(freshKey));

  // 3) Once all 2 seats are claimed, /thank-you stops echoing freshKey in HTML and shows the expired/localStorage shell
  await activateAndGetTicket(env, freshKey, "5555666677778888", "198.51.100.24");
  const rFullSeats = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${freshKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.24" },
    }),
    env
  );
  const htmlFull = await rFullSeats.text();
  assert.equal(htmlFull.includes(freshKey), false);
  assert.match(htmlFull, /This checkout page has expired/);
  assert.match(htmlFull, /localStorage\.getItem/);

  // 4) Expired session (>1 hour old, even with 0 seats claimed) never echoes oldKey in HTML
  const rOld = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${oldKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.25" },
    }),
    env
  );
  assert.equal(rOld.status, 200);
  const htmlOld = await rOld.text();
  assert.equal(htmlOld.includes(oldKey), false);
  assert.match(htmlOld, /This checkout page has expired/);
});

test("21. Optional RESEND_API_KEY + RECEIPT_FROM_EMAIL sends backup email once on first /thank-you, stores zero PII in SQLite, and never re-sends on refresh", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_resendOneTimeBackupEmail000000024";
  const buyerEmail = "buyer@example.com";
  const nowSec = Math.floor(Date.now() / 1000);
  const resendCalls = [];

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    APP_NAME: "SampleApp",
    APP_URL_SCHEME: "sampleapp",
    RESEND_API_KEY: "re_test_mock_key",
    RECEIPT_FROM_EMAIL: "SampleApp <keys@sampleapp.example>",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url, init) => {
      if (String(url) === "https://api.resend.com/emails") {
        resendCalls.push({
          headers: init.headers,
          body: JSON.parse(init.body),
        });
        return new Response(JSON.stringify({ id: "email_123" }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          ...PAID_SESSION_JSON,
          created: nowSec - 10,
          customer_details: { email: buyerEmail },
        }),
        { status: 200 }
      );
    },
  };

  // First /thank-you visit triggers exactly 1 Resend email via ctx.waitUntil
  const waitPromises = [];
  const ctx = { waitUntil(p) { waitPromises.push(p); } };
  const r1 = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${key}`, {
      headers: { "CF-Connecting-IP": "198.51.100.26" },
    }),
    env,
    ctx
  );
  assert.equal(r1.status, 200);
  await Promise.all(waitPromises);
  assert.equal(resendCalls.length, 1);
  assert.deepEqual(resendCalls[0].body.to, [buyerEmail]);
  assert.ok(resendCalls[0].body.text.includes(key));
  // Webmail drops `sampleapp://` links, so the email links to the Worker's https /open page with the key in the fragment.
  assert.ok(resendCalls[0].body.text.includes(`https://activate.example.com/open#key=${key}`));
  assert.ok(typeof resendCalls[0].body.html === "string" && resendCalls[0].body.html.includes(`<a href="https://activate.example.com/open#key=${key}"`));
  assert.equal(resendCalls[0].body.html.includes("sampleapp://"), false);
  assert.ok(resendCalls[0].body.html.includes(key));
  assert.ok(resendCalls[0].headers["Idempotency-Key"].startsWith("thank-you-receipt-"));

  // Repeated /thank-you refreshes across multiple IPs never trigger a 2nd email
  for (const ip of ["198.51.100.26", "198.51.100.27", "198.51.100.28"]) {
    const r = await worker.fetch(
      new Request(`https://activate.example.com/thank-you?session_id=${key}`, {
        headers: { "CF-Connecting-IP": ip },
      }),
      env
    );
    assert.equal(r.status, 200);
  }
  assert.equal(resendCalls.length, 1);

  // Verify zero PII (buyerEmail) exists anywhere in the Durable Object's SQLite tables
  const keyHash = await sha256HexTest("seatstamp-key-v1|" + key);
  const stub = env.SEAT_DO.get("lic:" + keyHash);
  const metaRows = stub.sql.exec(`SELECT key, value FROM meta`).toArray();
  const serializedMeta = JSON.stringify(metaRows);
  assert.equal(serializedMeta.includes(buyerEmail), false, "buyer email must never be stored in SQLite");
  assert.ok(metaRows.some((r) => r.key === "email_claimed_at" && Number(r.value) > 0));
  assert.ok(metaRows.some((r) => r.key === "email_attempts" && r.value === "1"));

  // And subsequent Mac activation works normally (verifies with Stripe since verified_at was 0)
  const act = await activateAndGetTicket(env, key, "1111222233334444", "198.51.100.26");
  assert.equal(act.seatsUsed, 1);
});

function makeBackupEmailEnv(privB64, buyerEmail, resendHandler) {
  const nowSec = Math.floor(Date.now() / 1000);
  const resendCalls = [];
  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    APP_NAME: "SampleApp",
    APP_URL_SCHEME: "sampleapp",
    RESEND_API_KEY: "re_test_mock_key",
    RECEIPT_FROM_EMAIL: "SampleApp <keys@sampleapp.example>",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url, init) => {
      if (String(url) === "https://api.resend.com/emails") {
        resendCalls.push({ headers: init.headers, body: JSON.parse(init.body) });
        return resendHandler(resendCalls.length);
      }
      return new Response(
        JSON.stringify({ ...PAID_SESSION_JSON, created: nowSec - 10, customer_details: { email: buyerEmail } }),
        { status: 200 }
      );
    },
  };
  return { env, resendCalls };
}

async function loadThankYouAndWait(env, key, ip) {
  const waitPromises = [];
  const ctx = { waitUntil(p) { waitPromises.push(p); } };
  const r = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": ip } }),
    env,
    ctx
  );
  await Promise.all(waitPromises);
  return r;
}

async function readThankYouEmailMeta(env, key) {
  const keyHash = await sha256HexTest("seatstamp-key-v1|" + key);
  const stub = env.SEAT_DO.get("lic:" + keyHash);
  const rows = stub.sql.exec(`SELECT key, value FROM meta`).toArray();
  const meta = Object.fromEntries(rows.map((r) => [r.key, String(r.value)]));
  return { meta, serialized: JSON.stringify(rows) };
}

test("21b. backup email: a failed send releases the claim and the next /thank-you load retries, at most 3 attempts", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const buyerEmail = "retry-buyer@example.com";
  const ips = ["198.51.100.141", "198.51.100.142", "198.51.100.143", "198.51.100.144"];

  // Scenario 1: 500, 500, 200.
  {
    const key = "cs_live_backupEmailRetry500500200000000001";
    const statuses = [500, 500, 200];
    const { env, resendCalls } = makeBackupEmailEnv(privB64, buyerEmail, (n) =>
      new Response("{}", { status: statuses[n - 1] ?? 200 })
    );
    for (let i = 0; i < 4; i++) {
      const r = await loadThankYouAndWait(env, key, ips[i]);
      assert.equal(r.status, 200);
      const { meta, serialized } = await readThankYouEmailMeta(env, key);
      assert.equal(serialized.includes(buyerEmail), false, "buyer email must never be stored in SQLite");
      if (i < 2) {
        assert.equal(meta.email_claimed_at, undefined, `claim must be released after failed load ${i + 1}`);
      } else {
        assert.ok(Number(meta.email_claimed_at) > 0, `claim must stay after load ${i + 1}`);
      }
      assert.equal(meta.email_attempts, String(Math.min(i + 1, 3)));
    }
    assert.equal(resendCalls.length, 3);
    const idem = resendCalls.map((c) => c.headers["Idempotency-Key"]);
    assert.ok(idem[0].startsWith("thank-you-receipt-"));
    assert.ok(idem.every((k) => k === idem[0]));
  }

  // Scenario 2: the provider always answers 500; load 4 does not call it.
  {
    const key = "cs_live_backupEmailRetryAlways500000000002";
    const { env, resendCalls } = makeBackupEmailEnv(privB64, buyerEmail, () => new Response("{}", { status: 500 }));
    for (let i = 0; i < 4; i++) {
      const r = await loadThankYouAndWait(env, key, ips[i]);
      assert.equal(r.status, 200);
      assert.equal(resendCalls.length, Math.min(i + 1, 3));
    }
    const { meta } = await readThankYouEmailMeta(env, key);
    assert.equal(meta.email_claimed_at, undefined);
    assert.equal(meta.email_attempts, "3");
  }

  // Scenario 3: the provider fetch throws; the claim is released.
  {
    const key = "cs_live_backupEmailRetryThrows0000000000003";
    const { env, resendCalls } = makeBackupEmailEnv(privB64, buyerEmail, () => {
      throw new TypeError("network down");
    });
    const r = await loadThankYouAndWait(env, key, ips[0]);
    assert.equal(r.status, 200);
    assert.equal(resendCalls.length, 1);
    const { meta } = await readThankYouEmailMeta(env, key);
    assert.equal(meta.email_claimed_at, undefined);
    assert.equal(meta.email_attempts, "1");
  }
});

test("21c. backup email is sent when the session was verified through the cache first", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const buyerEmail = "cached-buyer@example.com";
  const key = "cs_live_backupEmailAfterCacheHit000000004";
  const { env, resendCalls } = makeBackupEmailEnv(privB64, buyerEmail, () =>
    new Response(JSON.stringify({ id: "email_1" }), { status: 200 })
  );
  const act = await activateAndGetTicket(env, key, "5555666677778888", "198.51.100.150");
  assert.equal(act.seatsUsed, 1);
  const r = await loadThankYouAndWait(env, key, "198.51.100.151");
  assert.equal(r.status, 200);
  assert.equal(resendCalls.length, 1);
  assert.deepEqual(resendCalls[0].body.to, [buyerEmail]);
});

function makeClaimCheckoutRequest(handoff, seat, { fallbackSearch = false, ip = "198.51.100.30", headers = {} } = {}) {
  return new Request("https://activate.example.com/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip, ...headers },
    body: JSON.stringify({ action: "claim_checkout", handoff, seat, fallbackSearch }),
  });
}

// Records a token as first seen `agoMs` earlier, bound to `seat`, so a following `fallbackSearch: true` claim
// from the same seat may search. Always pass the seat of the claim that follows: the token binds to the first seat.
async function seedHandoffFirstSeen(env, handoff, seat, agoMs = 31_000) {
  const stub = env.SEAT_DO.get(env.SEAT_DO.idFromName("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff))));
  return stub.inspectCheckoutHandoff({ nowMs: Date.now() - agoMs, reserveSearchCooldown: false, seat });
}

test("22a. Fast-path client_reference_id handoff: GET /thank-you records ephemeral handoff and POST claim_checkout returns 200 with sessionId + verifiable LK1- ticket", async () => {
  const { privB64, publicKey } = await generateEd25519KeyPairB64();
  const sessionKey = "cs_live_handoffFastPathSession00000000025";
  const handoff = "chk_0123456789abcdef0123456789abcdef";
  const nowSec = Math.floor(Date.now() / 1000);

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    TICKET_SCHEME: "MYAPP-V1",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async () =>
      new Response(
        JSON.stringify({
          ...PAID_SESSION_JSON,
          id: sessionKey,
          created: nowSec - 15,
          client_reference_id: handoff,
        }),
        { status: 200 }
      ),
  };

  // 1) Before /thank-you is visited (and fallbackSearch: false), claim_checkout returns 202 pending
  const rPending = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444"), env);
  assert.equal(rPending.status, 202);
  assert.deepEqual(await rPending.json(), { status: "pending" });

  // 2) Buyer's browser lands on /thank-you?session_id=cs_live_...
  const rThankYou = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${sessionKey}`, {
      headers: { "CF-Connecting-IP": "198.51.100.30" },
    }),
    env
  );
  assert.equal(rThankYou.status, 200);

  // 3) Next background poll from the Mac app claims the seat and receives { status: "activated", key: sessionKey, ticket, ... }
  const rClaim1 = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444"), env);
  assert.equal(rClaim1.status, 200);
  const body1 = await rClaim1.json();
  assert.equal(body1.status, "activated");
  assert.equal(body1.key, sessionKey);
  assert.equal(body1.seatsUsed, 1);
  assert.equal(body1.maxSeats, 2);

  const [payloadB64, sigB64] = body1.ticket.slice(4).split(".");
  const sigOk = await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    Buffer.from(sigB64, "base64url"),
    Buffer.from(payloadB64, "base64url")
  );
  assert.equal(sigOk, true);

  // 3b) Another seat code polling the same handoff is refused and never sees the key or a ticket
  const rOtherSeat = await worker.fetch(makeClaimCheckoutRequest(handoff, "5555666677778888"), env);
  assert.equal(rOtherSeat.status, 403);
  const otherBody = await rOtherSeat.json();
  assert.deepEqual(otherBody, { error: "handoff_seat_mismatch" });
  assert.equal("key" in otherBody, false);
  const licStub22a = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + sessionKey)));
  assert.deepEqual(licStub22a._readRecord().seats, ["1111222233334444"]);

  // 4) Retrying claim_checkout from the same Mac (e.g. dropped response) is idempotent and keeps seatsUsed === 1
  const rClaimRetry = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444"), env);
  assert.equal(rClaimRetry.status, 200);
  const bodyRetry = await rClaimRetry.json();
  assert.equal(bodyRetry.key, sessionKey);
  assert.equal(bodyRetry.seatsUsed, 1);
});

test("22b. Closed-tab fallback (fallbackSearch: true when /thank-you was never visited) uses a filtered Stripe list, pages once, verifies every candidate in order, enforces 15s cooldown, and rejects refunded/wrong-link sessions", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const handoffPending = "chk_aaaa1111bbbb2222cccc3333dddd4444";
  const handoffPaid = "chk_eeee5555ffff66660000777788889999";
  const paidSessionKey = "cs_live_closedTabFallbackPaidSession00026";
  const refundedSessionKey = "cs_live_closedTabRefundedSession00000027";
  const wrongLinkSessionKey = "cs_live_closedTabWrongPlinkSession000028";
  const fillerSessionKey = "cs_live_closedTabFillerPageOneSession0029";
  const listURLs = [];
  const retrievedIds = [];

  const listItem = (id, clientRef) => ({
    id,
    object: "checkout.session",
    livemode: true,
    mode: "payment",
    status: "complete",
    payment_status: "paid",
    client_reference_id: clientRef,
  });

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    TICKET_SCHEME: "MYAPP-V1",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    STRIPE_ALLOWED_PAYMENT_LINKS: "plink_myapp_usd",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      const urlStr = String(url);
      if (urlStr.startsWith("https://api.stripe.com/v1/checkout/sessions?")) {
        listURLs.push(new URL(urlStr));
        const isPageTwo = new URL(urlStr).searchParams.get("starting_after") === fillerSessionKey;
        // Page 1 holds only an unrelated completed session and has_more: true; the buyer's candidates are on page 2.
        const data = isPageTwo
          ? [
              listItem(wrongLinkSessionKey, handoffPaid),
              listItem(refundedSessionKey, handoffPaid),
              listItem(paidSessionKey, handoffPaid),
            ]
          : [listItem(fillerSessionKey, "chk_00000000000000000000000000000000")];
        return new Response(JSON.stringify({ object: "list", data, has_more: !isPageTwo }), { status: 200 });
      }
      for (const id of [wrongLinkSessionKey, refundedSessionKey, paidSessionKey]) {
        if (urlStr.includes(id)) retrievedIds.push(id);
      }
      if (urlStr.includes(wrongLinkSessionKey)) {
        return new Response(
          JSON.stringify({
            ...PAID_SESSION_JSON,
            id: wrongLinkSessionKey,
            payment_link: "plink_other_product",
            client_reference_id: handoffPaid,
          }),
          { status: 200 }
        );
      }
      if (urlStr.includes(refundedSessionKey)) {
        return new Response(
          JSON.stringify({
            ...PAID_SESSION_JSON,
            id: refundedSessionKey,
            payment_link: "plink_myapp_usd",
            client_reference_id: handoffPaid,
            payment_intent: {
              ...PAID_SESSION_JSON.payment_intent,
              latest_charge: {
                ...PAID_SESSION_JSON.payment_intent.latest_charge,
                refunded: true,
                amount_refunded: 900,
              },
            },
          }),
          { status: 200 }
        );
      }
      if (urlStr.includes(paidSessionKey)) {
        return new Response(
          JSON.stringify({
            ...PAID_SESSION_JSON,
            id: paidSessionKey,
            payment_link: "plink_myapp_usd",
            client_reference_id: handoffPaid,
          }),
          { status: 200 }
        );
      }
      return new Response("Not Found", { status: 404 });
    },
  };

  // 1) Unpaid handoff with fallbackSearch: true queries Stripe (2 pages), returns 202 pending, and enforces 15s cooldown on immediate retry
  await seedHandoffFirstSeen(env, handoffPending, "1111222233334444");
  const rPend1 = await worker.fetch(makeClaimCheckoutRequest(handoffPending, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.31" }), env);
  assert.equal(rPend1.status, 202);
  assert.equal(listURLs.length, 2);

  // The list URL is filtered server-side: completed sessions only, bounded to the 24h handoff TTL, pinned to the single allowlisted link
  const firstList = listURLs[0];
  assert.equal(firstList.searchParams.get("status"), "complete");
  assert.equal(firstList.searchParams.get("limit"), "100");
  assert.equal(firstList.searchParams.get("payment_link"), "plink_myapp_usd");
  const createdGte = Number(firstList.searchParams.get("created[gte]"));
  const nowSec = Math.floor(Date.now() / 1000);
  assert.ok(createdGte >= nowSec - 86_400 - 5 && createdGte <= nowSec - 86_400 + 5);
  assert.equal(firstList.searchParams.has("starting_after"), false);
  assert.equal(listURLs[1].searchParams.get("starting_after"), fillerSessionKey);

  const rPend2 = await worker.fetch(makeClaimCheckoutRequest(handoffPending, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.31" }), env);
  assert.equal(rPend2.status, 202);
  assert.equal(listURLs.length, 2, "15s per-handoff search cooldown prevents spamming Stripe list endpoint");

  // 2) Paid handoff: candidates are verified in list order, wrong-plink and refunded ones are rejected, paidSessionKey is claimed
  await seedHandoffFirstSeen(env, handoffPaid, "1111222233334444");
  const rPaid = await worker.fetch(makeClaimCheckoutRequest(handoffPaid, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.32" }), env);
  assert.equal(rPaid.status, 200);
  const bPaid = await rPaid.json();
  assert.equal(bPaid.status, "activated");
  assert.equal(bPaid.key, paidSessionKey);
  assert.equal(bPaid.seatsUsed, 1);
  assert.equal(listURLs.length, 4);
  assert.deepEqual(retrievedIds, [wrongLinkSessionKey, refundedSessionKey, paidSessionKey]);

  // 3) A repeat claim reads the recorded handoff and never lists Stripe again
  const rRepeat = await worker.fetch(makeClaimCheckoutRequest(handoffPaid, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.32" }), env);
  assert.equal(rRepeat.status, 200);
  assert.equal((await rRepeat.json()).key, paidSessionKey);
  assert.equal(listURLs.length, 4, "recorded handoff short-circuits further Stripe list calls");
});

test("22b2. Closed-tab fallback pins each list call to one allowlisted payment link", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const handoff = "chk_1234123412341234123412341234abcd";
  const seen = [];
  const mk = (links) => {
    let env;
    const doBinding = createSQLiteDOHarness(() => env);
    env = {
      ENVIRONMENT: "test",
      ED25519_PKCS8_B64: privB64,
      STRIPE_SECRET_KEY: "sk_live_mock_secret",
      SEAT_DO: doBinding,
      __TEST_FETCH: async (url) => {
        seen.push(new URL(String(url)).searchParams.get("payment_link"));
        return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
      },
    };
    if (links !== undefined) env.STRIPE_ALLOWED_PAYMENT_LINKS = links;
    return env;
  };
  const env1 = mk(undefined);
  const env2 = mk("plink_a, plink_b");
  await seedHandoffFirstSeen(env1, handoff, "1111222233334444");
  assert.equal((await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.40" }), env1)).status, 202);
  assert.deepEqual(seen, [null]);
  seen.length = 0;
  await seedHandoffFirstSeen(env2, handoff, "1111222233334444");
  assert.equal((await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.41" }), env2)).status, 202);
  assert.deepEqual(seen, ["plink_a", "plink_b"]);
});

test("22b3. claim_checkout polling has its own per-IP rate budget (30/min) and never starves a real activate (12/min)", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_claimBudgetIsolatedFromActivate030";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.42";
  const handoff = "chk_abcdabcdabcdabcdabcdabcdabcdabcd";

  // 13 pending polls exceed the 12/min activate budget but stay inside the 30/min claim budget
  for (let i = 0; i < 13; i++) {
    const r = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { ip }), env);
    assert.equal(r.status, 202);
  }
  // A real activation from the same IP still succeeds
  const act = await worker.fetch(makeActivateRequest(key, "1111222233334444", ip), env);
  assert.equal(act.status, 200);

  // And the claim budget itself is still enforced at 30
  for (let i = 13; i < 30; i++) {
    assert.equal((await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { ip }), env)).status, 202);
  }
  const r31 = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { ip }), env);
  assert.equal(r31.status, 429);
  assert.equal(r31.headers.get("Retry-After"), "30");
});

test("22b4. Closed-tab fallback surfaces Stripe outage or missing list permission as 502 upstream_unavailable, not 202 pending", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const handoff = "chk_feedfeedfeedfeedfeedfeedfeedfeed";
  let mode = "forbidden";
  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "rk_live_missing_list_scope",
    SEAT_DO: doBinding,
    __TEST_FETCH: async () => {
      if (mode === "forbidden") return new Response(JSON.stringify({ error: { message: "Insufficient permissions" } }), { status: 403 });
      if (mode === "outage") return new Response("Bad Gateway", { status: 502 });
      throw new TypeError("network down");
    },
  };

  // Restricted key lacking Checkout Sessions: Read on the list endpoint -> 502, not an endless 202
  await seedHandoffFirstSeen(env, handoff, "1111222233334444");
  const r1 = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.43" }), env);
  assert.equal(r1.status, 502);
  assert.deepEqual(await r1.json(), { error: "upstream_unavailable" });
  assert.equal(r1.headers.get("Retry-After"), "10");

  // Within the 15s cooldown the next poll does not hit Stripe again and reports pending (cooldown is the only thing gating it)
  mode = "outage";
  const r2 = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.43" }), env);
  assert.equal(r2.status, 202);

  // A different handoff during a Stripe 5xx outage -> 502 as well; network throw -> 502
  await seedHandoffFirstSeen(env, "chk_0000111122223333444455556666aaaa", "1111222233334444");
  await seedHandoffFirstSeen(env, "chk_0000111122223333444455556666bbbb", "1111222233334444");
  const r3 = await worker.fetch(makeClaimCheckoutRequest("chk_0000111122223333444455556666aaaa", "1111222233334444", { fallbackSearch: true, ip: "198.51.100.44" }), env);
  assert.equal(r3.status, 502);
  mode = "throw";
  const r4 = await worker.fetch(makeClaimCheckoutRequest("chk_0000111122223333444455556666bbbb", "1111222233334444", { fallbackSearch: true, ip: "198.51.100.45" }), env);
  assert.equal(r4.status, 502);

  // Without fallbackSearch nothing touches Stripe and the answer is a plain 202
  const r5 = await worker.fetch(makeClaimCheckoutRequest("chk_0000111122223333444455556666cccc", "1111222233334444", { ip: "198.51.100.46" }), env);
  assert.equal(r5.status, 202);
});

test("22b5. fallback search surfaces a verification error", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const handoff = "chk_b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5";
  const sessionKey = "cs_live_fallbackVerifyForbidden00000000033";
  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "rk_live_missing_charges_scope",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      const u = String(url);
      if (u.startsWith("https://api.stripe.com/v1/checkout/sessions?")) {
        const item = {
          ...PAID_SESSION_JSON,
          object: "checkout.session",
          id: sessionKey,
          client_reference_id: handoff,
          created: Math.floor(Date.now() / 1000) - 60,
        };
        return new Response(JSON.stringify({ object: "list", data: [item], has_more: false }), { status: 200 });
      }
      if (u.includes("expand[]") || u.includes("expand%5B%5D")) {
        return new Response(JSON.stringify({ error: { message: "Insufficient permissions" } }), { status: 403 });
      }
      return new Response(JSON.stringify({ error: { message: "unexpected" } }), { status: 500 });
    },
  };

  await seedHandoffFirstSeen(env, handoff, "1111222233334444");
  const r = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.47" }), env);
  assert.equal(r.status, 502);
  assert.deepEqual(await r.json(), { error: "upstream_unavailable" });
  assert.equal(r.headers.get("Retry-After"), "10");

  const handoffStub = env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff)));
  const meta = Object.fromEntries(handoffStub.sql.exec(`SELECT key, value FROM meta`).toArray().map((row) => [row.key, row.value]));
  assert.equal("handoff_session_id" in meta, false);
});

test("22b6. fallback search needs a token first seen 30 s earlier, stops after 40 searches, and lists the whole account only with no allowlist or more than 8 links", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const seat = "1111222233334444";
  const listURLs = [];
  const mk = (links) => {
    let env;
    const doBinding = createSQLiteDOHarness(() => env);
    env = {
      ENVIRONMENT: "test",
      ED25519_PKCS8_B64: privB64,
      STRIPE_SECRET_KEY: "sk_live_mock_secret",
      SEAT_DO: doBinding,
      __TEST_FETCH: async (url) => {
        listURLs.push(new URL(String(url)));
        return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
      },
    };
    if (links !== undefined) env.STRIPE_ALLOWED_PAYMENT_LINKS = links;
    return env;
  };
  const handoffStubFor = async (env, handoff) =>
    env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff)));
  const env = mk(undefined);

  // A freshly invented token never reaches Stripe.
  const fresh = "chk_b6b6b6b6b6b6b6b6b6b6b6b6b6b60001";
  const r1 = await worker.fetch(makeClaimCheckoutRequest(fresh, seat, { fallbackSearch: true, ip: "198.51.100.120" }), env);
  assert.equal(r1.status, 202);
  assert.equal(listURLs.length, 0);
  const freshMeta = Object.fromEntries((await handoffStubFor(env, fresh)).sql.exec(`SELECT key, value FROM meta`).toArray().map((r) => [r.key, r.value]));
  assert.ok(Number(freshMeta.handoff_first_seen_ms) > 0);
  assert.equal("handoff_search_count" in freshMeta, false);

  // A token first seen 31 seconds earlier may search.
  const aged = "chk_b6b6b6b6b6b6b6b6b6b6b6b6b6b60002";
  await seedHandoffFirstSeen(env, aged, seat);
  const r2 = await worker.fetch(makeClaimCheckoutRequest(aged, seat, { fallbackSearch: true, ip: "198.51.100.121" }), env);
  assert.equal(r2.status, 202);
  assert.equal(listURLs.length, 1);
  const agedMeta = Object.fromEntries((await handoffStubFor(env, aged)).sql.exec(`SELECT key, value FROM meta`).toArray().map((r) => [r.key, r.value]));
  assert.equal(agedMeta.handoff_search_count, "1");

  // After 40 searches no further list call happens.
  const spent = "chk_b6b6b6b6b6b6b6b6b6b6b6b6b6b60003";
  await seedHandoffFirstSeen(env, spent, seat);
  (await handoffStubFor(env, spent)).sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('handoff_search_count', '40')`);
  const r3 = await worker.fetch(makeClaimCheckoutRequest(spent, seat, { fallbackSearch: true, ip: "198.51.100.122" }), env);
  assert.equal(r3.status, 202);
  assert.equal(listURLs.length, 1);

  // Nine allowlisted links: one list call without payment_link.
  listURLs.length = 0;
  const nineLinks = Array.from({ length: 9 }, (_, i) => `plink_n${i}`).join(",");
  const env9 = mk(nineLinks);
  const wide = "chk_b6b6b6b6b6b6b6b6b6b6b6b6b6b60004";
  await seedHandoffFirstSeen(env9, wide, seat);
  const r4 = await worker.fetch(makeClaimCheckoutRequest(wide, seat, { fallbackSearch: true, ip: "198.51.100.123" }), env9);
  assert.equal(r4.status, 202);
  assert.equal(listURLs.length, 1);
  assert.equal(listURLs[0].searchParams.has("payment_link"), false);
});

test("22c. Handoff 24h alarm() wipes handoff:<hash> DO storage (0 bytes) while leaving lic:<keyHash> seat records untouched; handoff DOs are meta-only and arm the alarm once", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const sessionKey = "cs_live_handoffAlarmCleanupSession0000029";
  const handoff = "chk_99998888777766665555444433332222";

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      if (String(url).startsWith("https://api.stripe.com/v1/checkout/sessions?")) {
        return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          ...PAID_SESSION_JSON,
          id: sessionKey,
          created: Math.floor(Date.now() / 1000) - 10,
          client_reference_id: handoff,
        }),
        { status: 200 }
      );
    },
  };
  const thankYou = (path, ip) =>
    worker.fetch(new Request(`https://activate.example.com/${path}?session_id=${sessionKey}`, { headers: { "CF-Connecting-IP": ip } }), env);

  // /success is an alias of /thank-you and records the handoff too; repeat views do not rewrite or re-arm
  assert.equal((await thankYou("success", "198.51.100.33")).status, 200);
  assert.equal((await thankYou("thank-you", "198.51.100.33")).status, 200);
  const claimRes = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { ip: "198.51.100.33" }), env);
  assert.equal(claimRes.status, 200);

  const handoffHash = await sha256HexTest("seatstamp-key-v1|handoff|" + handoff);
  const handoffStub = env.SEAT_DO.get("handoff:" + handoffHash);
  const keyHash = await sha256HexTest("seatstamp-key-v1|" + sessionKey);
  const licStub = env.SEAT_DO.get("lic:" + keyHash);

  assert.equal(handoffStub._hasSchema(), true);
  assert.equal(handoffStub.ctx.__alarmCalls, 1, "alarm armed exactly once across two page views and a claim");
  const scheduledAlarm = await handoffStub.ctx.storage.getAlarm();
  assert.ok(Number.isFinite(scheduledAlarm) && scheduledAlarm > Date.now() + 23 * 3600 * 1000);
  const handoffTables = handoffStub.sql.exec(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).toArray().map((r) => r.name);
  assert.deepEqual(handoffTables, ["meta"], "handoff DOs never create the seats table");
  const handoffMeta = JSON.stringify(handoffStub.sql.exec(`SELECT key, value FROM meta`).toArray());
  assert.equal(handoffMeta.includes("tag"), false);

  // Firing alarm() on handoff:<hash> wipes it completely (0 tables)
  await handoffStub.alarm();
  assert.equal(handoffStub._hasSchema(), false);

  // Firing alarm() on lic:<keyHash> is a no-op and never deletes real license seat records
  await licStub.alarm();
  assert.equal(licStub._hasSchema(), true);
  assert.deepEqual(licStub._readRecord().seats, ["1111222233334444"]);

  // A cooldown-only handoff (fallbackSearch fired, nothing found) is also wiped by alarm()
  const lonelyHandoff = "chk_0000aaaa0000bbbb0000cccc0000dddd";
  assert.equal((await worker.fetch(makeClaimCheckoutRequest(lonelyHandoff, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.35" }), env)).status, 202);
  const lonelyStub = env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + lonelyHandoff)));
  assert.equal(lonelyStub._hasSchema(), true);
  assert.equal(lonelyStub.ctx.__alarmCalls, 1);
  await lonelyStub.alarm();
  assert.equal(lonelyStub._hasSchema(), false);

  // If the alarm is late, inspectCheckoutHandoff also drops an expired record on read instead of serving it
  const staleHandoff = "chk_1111aaaa1111bbbb1111cccc1111dddd";
  const staleStub = env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + staleHandoff)));
  await staleStub.recordCheckoutHandoff({ sessionId: sessionKey, nowMs: Date.now() - 25 * 3600 * 1000 });
  assert.equal(staleStub._hasSchema(), true);
  const rStale = await worker.fetch(makeClaimCheckoutRequest(staleHandoff, "1111222233334444", { ip: "198.51.100.36" }), env);
  assert.equal(rStale.status, 202);
  assert.equal(staleStub._hasSchema(), false, "expired handoff is wiped on read");
});

test("22d. claim_checkout rejects invalid handoff tokens, bad seats, and cross-site Origin CSRF", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = makePaidEnv(privB64);

  // Invalid handoff token formats -> 400 invalid_params
  for (const badHandoff of ["", "chk_short", "chk_" + "G".repeat(32), "chk_" + "A".repeat(32), "cs_live_123456789012345678901234"]) {
    const r = await worker.fetch(makeClaimCheckoutRequest(badHandoff, "1111222233334444", { ip: "198.51.100.34" }), env);
    assert.equal(r.status, 400);
    assert.equal((await r.json()).error, "invalid_params");
  }

  // Bad seat -> 400 invalid_params
  const rBadSeat = await worker.fetch(makeClaimCheckoutRequest("chk_0123456789abcdef0123456789abcdef", "not-16-hex", { ip: "198.51.100.34" }), env);
  assert.equal(rBadSeat.status, 400);

  // Cross-site Origin header -> 403 forbidden_origin
  const rCsrf = await worker.fetch(
    makeClaimCheckoutRequest("chk_0123456789abcdef0123456789abcdef", "1111222233334444", {
      ip: "198.51.100.34",
      headers: { Origin: "https://evil.example" },
    }),
    env
  );
  assert.equal(rCsrf.status, 403);
  assert.equal((await rCsrf.json()).error, "forbidden_origin");
});

test("22e. claim_checkout propagates 403 invalid_key for a refunded session (negative-cached) and 409 seat_limit_reached when the lic DO is full", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const refundedKey = "cs_live_claimRefundedAfterThankYou0000031";
  const fullKey = "cs_live_claimSeatLimitReachedSession00032";
  const refundedHandoff = "chk_1111aaaa2222bbbb3333cccc4444dddd";
  const fullHandoff = "chk_5555eeee6666ffff7777000088881111";
  let refunded = false;
  let stripeCalls = 0;

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url) => {
      stripeCalls += 1;
      const u = String(url);
      const isRefundedKey = u.includes(refundedKey);
      const json = structuredClone(PAID_SESSION_JSON);
      json.id = isRefundedKey ? refundedKey : fullKey;
      json.created = Math.floor(Date.now() / 1000) - 10;
      json.client_reference_id = isRefundedKey ? refundedHandoff : fullHandoff;
      if (isRefundedKey && refunded) {
        json.payment_intent.latest_charge.refunded = true;
        json.payment_intent.latest_charge.amount_refunded = 900;
      }
      return new Response(JSON.stringify(json), { status: 200 });
    },
  };
  const thankYou = (key, ip) =>
    worker.fetch(new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": ip } }), env);

  // 1) Buyer lands on /thank-you (paid), then the charge is refunded before the app claims.
  assert.equal((await thankYou(refundedKey, "198.51.100.50")).status, 200);
  refunded = true;
  __resetIsolateStateForTests(env); // drop the 45s recent-valid cache so the claim re-verifies with Stripe
  const rRefunded = await worker.fetch(makeClaimCheckoutRequest(refundedHandoff, "1111222233334444", { ip: "198.51.100.50" }), env);
  assert.equal(rRefunded.status, 403);
  assert.deepEqual(await rRefunded.json(), { error: "invalid_key" });

  // Refunded key is negative-cached: a second claim short-circuits without another Stripe call
  const before = stripeCalls;
  const rRefundedAgain = await worker.fetch(makeClaimCheckoutRequest(refundedHandoff, "1111222233334444", { ip: "198.51.100.50" }), env);
  assert.equal(rRefundedAgain.status, 403);
  assert.equal(stripeCalls, before);

  // 2) Two Macs already hold the seats for fullKey; a third Mac's claim_checkout gets 409 seat_limit_reached
  assert.equal((await thankYou(fullKey, "198.51.100.51")).status, 200);
  await activateAndGetTicket(env, fullKey, "aaaa000000000001", "198.51.100.51");
  await activateAndGetTicket(env, fullKey, "aaaa000000000002", "198.51.100.51");
  const rFull = await worker.fetch(makeClaimCheckoutRequest(fullHandoff, "aaaa000000000003", { ip: "198.51.100.51" }), env);
  assert.equal(rFull.status, 409);
  assert.equal((await rFull.json()).error, "seat_limit_reached");

  // The 409 claim bound the handoff to aaaa000000000003: another seat code is refused, the bound seat still gets 409
  const rOtherSeat = await worker.fetch(makeClaimCheckoutRequest(fullHandoff, "aaaa000000000001", { ip: "198.51.100.51" }), env);
  assert.equal(rOtherSeat.status, 403);
  assert.equal((await rOtherSeat.json()).error, "handoff_seat_mismatch");
  const rFullAgain = await worker.fetch(makeClaimCheckoutRequest(fullHandoff, "aaaa000000000003", { ip: "198.51.100.51" }), env);
  assert.equal(rFullAgain.status, 409);
  assert.equal((await rFullAgain.json()).error, "seat_limit_reached");
});

test("22g. /thank-you records a handoff only for a fresh session", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const nowSec = () => Math.floor(Date.now() / 1000);
  const sessions = new Map();
  const makeEnv = (extra = {}) => {
    let env;
    const doBinding = createSQLiteDOHarness(() => env);
    env = {
      ENVIRONMENT: "test",
      ED25519_PKCS8_B64: privB64,
      STRIPE_SECRET_KEY: "sk_live_mock_secret",
      SEAT_DO: doBinding,
      __TEST_FETCH: async (url) => {
        const u = String(url);
        if (u.startsWith("https://api.stripe.com/v1/checkout/sessions?")) {
          return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
        }
        const id = decodeURIComponent(u.split("/v1/checkout/sessions/")[1].split("?")[0]);
        const s = sessions.get(id);
        const json = { ...PAID_SESSION_JSON, id, client_reference_id: s.handoff };
        if (s.ageSec !== undefined) json.created = nowSec() - s.ageSec;
        return new Response(JSON.stringify(json), { status: 200 });
      },
      ...extra,
    };
    return env;
  };
  const thankYou = (env, sessionId, ip) =>
    worker.fetch(new Request(`https://activate.example.com/thank-you?session_id=${sessionId}`, { headers: { "CF-Connecting-IP": ip } }), env);
  const handoffStubFor = async (env, handoff) =>
    env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff)));

  // (a) session created 2 hours ago, default 1-hour window: not recorded
  const envA = makeEnv();
  sessions.set("cs_live_handoffFreshnessTwoHoursOld000000a", { handoff: "chk_aaaa0000aaaa0000aaaa0000aaaa0001", ageSec: 2 * 3600 });
  assert.equal((await thankYou(envA, "cs_live_handoffFreshnessTwoHoursOld000000a", "198.51.100.71")).status, 200);
  assert.equal((await handoffStubFor(envA, "chk_aaaa0000aaaa0000aaaa0000aaaa0001"))._hasSchema(), false);
  const claimA = await worker.fetch(makeClaimCheckoutRequest("chk_aaaa0000aaaa0000aaaa0000aaaa0001", "1111222233334444", { ip: "198.51.100.71" }), envA);
  assert.equal(claimA.status, 202);

  // (b) session created 30 minutes ago: recorded, the claim activates
  const envB = makeEnv();
  sessions.set("cs_live_handoffFreshnessThirtyMinutes0000b", { handoff: "chk_bbbb0000bbbb0000bbbb0000bbbb0002", ageSec: 30 * 60 });
  assert.equal((await thankYou(envB, "cs_live_handoffFreshnessThirtyMinutes0000b", "198.51.100.72")).status, 200);
  const claimB = await worker.fetch(makeClaimCheckoutRequest("chk_bbbb0000bbbb0000bbbb0000bbbb0002", "1111222233334444", { ip: "198.51.100.72" }), envB);
  assert.equal(claimB.status, 200);

  // (c) a 48-hour thank-you window still records nothing older than 24 hours
  const envC = makeEnv({ THANK_YOU_WINDOW_SECONDS: "172800" });
  sessions.set("cs_live_handoffFreshnessTwentyFiveHours00c", { handoff: "chk_cccc0000cccc0000cccc0000cccc0003", ageSec: 25 * 3600 });
  assert.equal((await thankYou(envC, "cs_live_handoffFreshnessTwentyFiveHours00c", "198.51.100.73")).status, 200);
  assert.equal((await handoffStubFor(envC, "chk_cccc0000cccc0000cccc0000cccc0003"))._hasSchema(), false);

  // (d) a session without a creation time is not recorded
  const envD = makeEnv();
  sessions.set("cs_live_handoffFreshnessNoCreatedField000d", { handoff: "chk_dddd0000dddd0000dddd0000dddd0004" });
  assert.equal((await thankYou(envD, "cs_live_handoffFreshnessNoCreatedField000d", "198.51.100.74")).status, 200);
  assert.equal((await handoffStubFor(envD, "chk_dddd0000dddd0000dddd0000dddd0004"))._hasSchema(), false);

  // A fallback search arms the alarm once; recording the session later re-arms it for a full 24 hours.
  const envE = makeEnv();
  const handoffE = "chk_eeee0000eeee0000eeee0000eeee0005";
  sessions.set("cs_live_handoffFreshnessRearmAlarm000000e", { handoff: handoffE, ageSec: 10 });
  await seedHandoffFirstSeen(envE, handoffE, "1111222233334444");
  const search = await worker.fetch(makeClaimCheckoutRequest(handoffE, "1111222233334444", { fallbackSearch: true, ip: "198.51.100.75" }), envE);
  assert.equal(search.status, 202);
  const stubE = await handoffStubFor(envE, handoffE);
  assert.equal(stubE.ctx.__alarmCalls, 1);
  const recordedAt = Date.now();
  assert.equal((await thankYou(envE, "cs_live_handoffFreshnessRearmAlarm000000e", "198.51.100.75")).status, 200);
  assert.equal(stubE.ctx.__alarmCalls, 2);
  assert.ok((await stubE.ctx.storage.getAlarm()) >= recordedAt + (23 * 60 + 59) * 60 * 1000);
});

test("22f. handoff binds at the first poll", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = makePaidEnv(privB64);
  const handoff = "chk_22f22f22f22f22f22f22f22f22f22f22";
  const ip = "198.51.100.52";

  const rA = await worker.fetch(makeClaimCheckoutRequest(handoff, "1111222233334444", { ip }), env);
  assert.equal(rA.status, 202);
  const rB = await worker.fetch(makeClaimCheckoutRequest(handoff, "5555666677778888", { ip }), env);
  assert.equal(rB.status, 403);
  assert.deepEqual(await rB.json(), { error: "handoff_seat_mismatch" });

  const handoffStub = env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff)));
  const meta = Object.fromEntries(handoffStub.sql.exec(`SELECT key, value FROM meta`).toArray().map((r) => [r.key, r.value]));
  assert.equal(meta.handoff_seat, "1111222233334444");
  assert.equal("tag" in meta, false);
  assert.equal(handoffStub.ctx.__alarmCalls, 1);

  await handoffStub.alarm();
  assert.equal(handoffStub._hasSchema(), false);
});

function makeRecoverRequest(email, ip = "198.51.100.60", headers = {}) {
  return new Request("https://activate.example.com/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip, ...headers },
    body: JSON.stringify({ action: "recover", email }),
  });
}

function makeWaitUntilCtx() {
  const promises = [];
  return { ctx: { waitUntil(p) { promises.push(p); } }, flush: () => Promise.all(promises), count: () => promises.length };
}

// Builds a Resend + Stripe mock for recovery tests. `sessionsByEmail` maps the exact (case-sensitive) email
// Stripe would match to the array of expanded session objects it returns.
function makeRecoveryEnv(privB64, sessionsByEmail, extra = {}) {
  const calls = { stripe: [], resend: [] };
  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    APP_NAME: "SampleApp",
    APP_URL_SCHEME: "sampleapp",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    STRIPE_ALLOWED_PAYMENT_LINKS: "plink_myapp_usd",
    RESEND_API_KEY: "re_test_mock_key",
    RECEIPT_FROM_EMAIL: "SampleApp <keys@sampleapp.example>",
    SEAT_DO: doBinding,
    __TEST_FETCH: async (url, init) => {
      const u = new URL(String(url));
      if (u.hostname === "api.resend.com") {
        calls.resend.push({ headers: init.headers, body: JSON.parse(init.body) });
        return new Response(JSON.stringify({ id: "email_recover" }), { status: 200 });
      }
      if (env.__stripeGate) await env.__stripeGate;
      const single = /\/v1\/checkout\/sessions\/(cs_[A-Za-z0-9_]+)$/.exec(u.pathname);
      if (single) {
        const found = Object.values(sessionsByEmail).flat().find((s) => s.id === single[1]);
        return found
          ? new Response(JSON.stringify(found), { status: 200 })
          : new Response(JSON.stringify({ error: { message: "No such checkout.session" } }), { status: 404 });
      }
      calls.stripe.push(u);
      const emailParam = u.searchParams.get("customer_details[email]");
      const data = sessionsByEmail[emailParam] || [];
      return new Response(JSON.stringify({ object: "list", data, has_more: false }), { status: 200 });
    },
    ...extra,
  };
  return { env, calls };
}

function paidSession(id, email, overrides = {}) {
  return {
    ...structuredClone(PAID_SESSION_JSON),
    id,
    payment_link: "plink_myapp_usd",
    customer_details: { email },
    ...overrides,
  };
}

test("23a. recover: valid purchase email -> 200 {ok:true}; waitUntil runs one expanded Stripe list, drops refunded/wrong-plink/unpaid sessions, sends one Resend email with only valid keys + deep links", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const email = "buyer@example.com";
  const goodA = "cs_live_recoverValidSessionAlpha000000040";
  const goodB = "cs_live_recoverValidSessionBravo000000041";
  const refundedId = "cs_live_recoverRefundedSession0000000042";
  const wrongLinkId = "cs_live_recoverWrongPlinkSession000000043";
  const unpaidId = "cs_live_recoverUnpaidSession00000000044";
  const refunded = paidSession(refundedId, email);
  refunded.payment_intent.latest_charge.refunded = true;
  refunded.payment_intent.latest_charge.amount_refunded = 900;
  const { env, calls } = makeRecoveryEnv(privB64, {
    [email]: [
      paidSession(goodA, email),
      refunded,
      paidSession(wrongLinkId, email, { payment_link: "plink_other" }),
      paidSession(unpaidId, email, { payment_status: "unpaid" }),
      paidSession(goodB, email),
      paidSession(goodA, email), // duplicate id must be collapsed
    ],
  });

  // Hold every Stripe response until after the client has its 200: proves the response never waits on Stripe.
  let releaseStripe;
  env.__stripeGate = new Promise((resolve) => { releaseStripe = resolve; });
  const { ctx, flush } = makeWaitUntilCtx();
  const res = await worker.fetch(makeRecoverRequest(email), env, ctx);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  assert.equal(calls.stripe.length, 0, "no Stripe response has been consumed before the client got its 200");
  assert.equal(calls.resend.length, 0);
  releaseStripe();

  await flush();
  assert.equal(calls.stripe.length, 1, "one expanded list call, no N+1 per session");
  const q = calls.stripe[0].searchParams;
  assert.equal(q.get("customer_details[email]"), email);
  assert.equal(q.get("status"), "complete");
  assert.equal(q.get("limit"), "100");
  assert.equal(q.get("payment_link"), "plink_myapp_usd");
  assert.deepEqual(q.getAll("expand[]"), ["data.payment_intent.latest_charge"]);

  assert.equal(calls.resend.length, 1);
  const mail = calls.resend[0];
  assert.deepEqual(mail.body.to, [email]);
  assert.equal(mail.body.from, "SampleApp <keys@sampleapp.example>");
  assert.match(mail.headers["Idempotency-Key"], /^recover-[0-9a-f]{64}-\d+$/);
  assert.ok(mail.body.text.includes(goodA) && mail.body.text.includes(goodB));
  assert.ok(mail.body.text.includes(`https://activate.example.com/open#key=${goodA}`));
  assert.ok(typeof mail.body.html === "string");
  assert.ok(mail.body.html.includes(`<a href="https://activate.example.com/open#key=${goodA}"`));
  assert.ok(mail.body.html.includes(`<a href="https://activate.example.com/open#key=${goodB}"`));
  for (const bad of [refundedId, wrongLinkId, unpaidId]) {
    assert.equal(mail.body.text.includes(bad), false, `${bad} must not be emailed`);
    assert.equal(mail.body.html.includes(bad), false, `${bad} must not appear in HTML email`);
  }
  assert.equal((mail.body.text.match(new RegExp(goodA, "g")) || []).length, 2, "duplicate session id listed once (key line + deep link)");
});

test("23a2. recover: a session with a won dispute is emailed and one with a lost dispute is not", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const email = "disputed@example.com";
  const wonId = "cs_live_recoverWonDisputeSession00000045";
  const lostId = "cs_live_recoverLostDisputeSession0000046";
  const won = paidSession(wonId, email);
  won.payment_intent.id = "pi_recover_won";
  won.payment_intent.latest_charge.disputed = true;
  const lost = paidSession(lostId, email);
  lost.payment_intent.id = "pi_recover_lost";
  lost.payment_intent.latest_charge.disputed = true;
  const { env, calls } = makeRecoveryEnv(privB64, { [email]: [won, lost] });
  const disputeStatus = { pi_recover_won: "won", pi_recover_lost: "lost" };
  const stripeFetch = env.__TEST_FETCH;
  env.__TEST_FETCH = async (url, init) => {
    if (String(url).startsWith("https://api.stripe.com/v1/disputes?")) {
      const pi = new URL(String(url)).searchParams.get("payment_intent");
      const data = [{ id: "dp_" + pi, object: "dispute", status: disputeStatus[pi] }];
      return new Response(JSON.stringify({ object: "list", data, has_more: false }), { status: 200 });
    }
    return stripeFetch(url, init);
  };

  const { ctx, flush } = makeWaitUntilCtx();
  const res = await worker.fetch(makeRecoverRequest(email, "198.51.100.65"), env, ctx);
  assert.equal(res.status, 200);
  await flush();
  assert.equal(calls.resend.length, 1);
  assert.ok(calls.resend[0].body.text.includes(wonId));
  assert.equal(calls.resend[0].body.text.includes(lostId), false);
});

test("23b. recover: case-sensitivity fallback finds a session Stripe recorded as Denis@example.com when the buyer types denis@example.com", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const id = "cs_live_recoverCaseFallbackSession0000045";
  const { env, calls } = makeRecoveryEnv(privB64, { "Denis@example.com": [paidSession(id, "Denis@example.com")] });

  const { ctx, flush } = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest("denis@example.com", "198.51.100.61"), env, ctx)).status, 200);
  await flush();
  assert.deepEqual(
    calls.stripe.map((u) => u.searchParams.get("customer_details[email]")),
    ["denis@example.com", "Denis@example.com"],
    "lowercase first, then one capitalized fallback"
  );
  assert.equal(calls.resend.length, 1);
  assert.deepEqual(calls.resend[0].body.to, ["Denis@example.com"]);
  assert.ok(calls.resend[0].body.text.includes(id));

  // Mixed-case input: fallback is the exact typed casing, not the capitalized guess
  const { env: env2, calls: calls2 } = makeRecoveryEnv(privB64, { "DeNiS@Example.com": [paidSession(id, "DeNiS@Example.com")] });
  const w2 = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest("DeNiS@Example.com", "198.51.100.62"), env2, w2.ctx)).status, 200);
  await w2.flush();
  assert.deepEqual(calls2.stripe.map((u) => u.searchParams.get("customer_details[email]")), ["denis@example.com", "DeNiS@Example.com"]);
  assert.equal(calls2.resend.length, 1);
});

test("23c. recover: unknown email -> identical 200 {ok:true}, at most 2 Stripe lookups, 0 Resend emails (no enumeration leak)", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const { env, calls } = makeRecoveryEnv(privB64, {});
  const { ctx, flush } = makeWaitUntilCtx();
  const res = await worker.fetch(makeRecoverRequest("nobody@example.com", "198.51.100.63"), env, ctx);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  await flush();
  assert.equal(calls.stripe.length, 2, "lowercase lookup plus exactly one capitalized fallback");
  assert.equal(calls.resend.length, 0);

  // A known email and an unknown email produce byte-identical status, body, and headers
  const known = "known@example.com";
  const { env: envKnown } = makeRecoveryEnv(privB64, { [known]: [paidSession("cs_live_recoverKnownForHeaderParity0048", known)] });
  const wk = makeWaitUntilCtx();
  const rKnown = await worker.fetch(makeRecoverRequest(known, "198.51.100.64"), envKnown, wk.ctx);
  await wk.flush();
  assert.equal(rKnown.status, res.status);
  assert.deepEqual(Object.fromEntries(rKnown.headers), Object.fromEntries(res.headers));
});

test("23d. recover: 15-minute per-email cooldown returns the same 200 without Stripe/Resend calls; alarm() wipes recover:<hmac> and leaves lic: seats intact; zero PII stored", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const email = "cooldown@example.com";
  const id = "cs_live_recoverCooldownSession000000046";
  const { env, calls } = makeRecoveryEnv(privB64, { [email]: [paidSession(id, email)] });

  // Seed a real lic: record so we can prove alarm() on recover: never touches it
  await activateAndGetTicket(env, id, "1111222233334444", "198.51.100.65");
  calls.stripe.length = 0;

  const w1 = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest(email, "198.51.100.66"), env, w1.ctx)).status, 200);
  await w1.flush();
  assert.equal(calls.stripe.length, 1);
  assert.equal(calls.resend.length, 1);

  // Same spelling (different IP) inside the window: same 200, nothing sent
  {
    const w = makeWaitUntilCtx();
    const r = await worker.fetch(makeRecoverRequest(email, "198.51.100.67"), env, w.ctx);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true });
    await w.flush();
    assert.equal(w.count(), 0, "no background job scheduled during cooldown");
  }
  assert.equal(calls.stripe.length, 1);
  assert.equal(calls.resend.length, 1);

  // Another spelling has its own cooldown and schedules one job; the provider deduplicates on the lower-cased HMAC
  {
    const w = makeWaitUntilCtx();
    const r = await worker.fetch(makeRecoverRequest("  Cooldown@Example.COM ", "198.51.100.68"), env, w.ctx);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true });
    await w.flush();
    assert.equal(w.count(), 1, "a different spelling schedules its own job");
  }
  assert.equal(calls.stripe.length, 2);
  assert.equal(calls.resend.length, 2);

  // Inspect the recover: DO: HMAC-named, meta-only, no email string anywhere, alarm armed for +15m
  const hmacKey = await crypto.subtle.importKey("raw", new TextEncoder().encode("sk_live_mock_secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode("seatstamp-key-v1|recover|" + email));
  const emailHmac = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  assert.equal(calls.resend[0].headers["Idempotency-Key"].startsWith(`recover-${emailHmac}-`), true, "Idempotency-Key uses the same HMAC as the DO name");
  assert.equal(calls.resend[1].headers["Idempotency-Key"].startsWith(`recover-${emailHmac}-`), true, "another spelling keeps the lower-cased Idempotency-Key prefix");
  const recoverStub = env.SEAT_DO.get("recover:" + emailHmac);
  assert.equal(recoverStub._hasSchema(), true);
  const tables = recoverStub.sql.exec(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).toArray().map((r) => r.name);
  assert.deepEqual(tables, ["meta"]);
  const metaDump = JSON.stringify(recoverStub.sql.exec(`SELECT key, value FROM meta`).toArray());
  assert.equal(metaDump.toLowerCase().includes("cooldown@"), false, "email never stored");
  assert.equal(metaDump.includes(id), false, "session id never stored on the recover DO");
  assert.ok(metaDump.includes("recover_kind") && metaDump.includes("recover_claimed_at_ms"));
  const alarmAt = await recoverStub.ctx.storage.getAlarm();
  assert.ok(alarmAt > Date.now() + 14 * 60 * 1000 && alarmAt <= Date.now() + 15 * 60 * 1000 + 1000);

  // alarm() wipes the recover: instance completely but a lic: alarm is a no-op
  await recoverStub.alarm();
  assert.equal(recoverStub._hasSchema(), false);
  const licStub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + id)));
  await licStub.alarm();
  assert.deepEqual(licStub._readRecord().seats, ["1111222233334444"]);

  // After the wipe (cooldown over), a new request runs the lookup again
  const w2 = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest(email, "198.51.100.69"), env, w2.ctx)).status, 200);
  await w2.flush();
  assert.equal(calls.stripe.length, 3);
  assert.equal(calls.resend.length, 3);
});

async function recoverDoNameForTest(typedEmail) {
  const hmacKey = await crypto.subtle.importKey("raw", new TextEncoder().encode("sk_live_mock_secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode("seatstamp-key-v1|recover|" + typedEmail));
  return "recover:" + [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("23g. recover releases the cooldown on Stripe or provider failure and keeps it on a clean miss", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const sendRecover = async (env, email, ip) => {
    const w = makeWaitUntilCtx();
    const r = await worker.fetch(makeRecoverRequest(email, ip), env, w.ctx);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true });
    await w.flush();
    return w.count();
  };

  // Stripe 500 on the list call: the cooldown is released and the next request runs a new job.
  {
    const email = "stripe-down@example.com";
    const { env, calls } = makeRecoveryEnv(privB64, {});
    env.__TEST_FETCH = async (url) => {
      calls.stripe.push(new URL(String(url)));
      return new Response(JSON.stringify({ error: { message: "boom" } }), { status: 500 });
    };
    assert.equal(await sendRecover(env, email, "198.51.100.80"), 1);
    assert.equal(calls.stripe.length, 2, "lower-cased lookup plus one fallback spelling");
    assert.equal(env.SEAT_DO.get(await recoverDoNameForTest(email))._hasSchema(), false, "cooldown released");
    assert.equal(await sendRecover(env, email, "198.51.100.81"), 1, "a new job is scheduled at once");
    assert.equal(calls.resend.length, 0);
  }

  // Provider 500 after a found key: same result.
  {
    const email = "provider-down@example.com";
    const id = "cs_live_recoverProviderDownSession0000081";
    const { env, calls } = makeRecoveryEnv(privB64, { [email]: [paidSession(id, email)] });
    const stripeFetch = env.__TEST_FETCH;
    env.__TEST_FETCH = async (url, init) => {
      if (new URL(String(url)).hostname === "api.resend.com") {
        calls.resend.push({ headers: init.headers, body: JSON.parse(init.body) });
        return new Response(JSON.stringify({ message: "provider error" }), { status: 500 });
      }
      return stripeFetch(url, init);
    };
    assert.equal(await sendRecover(env, email, "198.51.100.82"), 1);
    assert.equal(calls.resend.length, 1);
    assert.equal(env.SEAT_DO.get(await recoverDoNameForTest(email))._hasSchema(), false, "cooldown released");
    assert.equal(await sendRecover(env, email, "198.51.100.83"), 1, "a new job is scheduled at once");
    assert.equal(calls.resend.length, 2);
    assert.equal(calls.resend[0].headers["Idempotency-Key"], calls.resend[1].headers["Idempotency-Key"]);
  }

  // Stripe 200 with no sessions: the cooldown stays.
  {
    const email = "clean-miss@example.com";
    const { env, calls } = makeRecoveryEnv(privB64, {});
    assert.equal(await sendRecover(env, email, "198.51.100.84"), 1);
    assert.equal(env.SEAT_DO.get(await recoverDoNameForTest(email))._hasSchema(), true, "cooldown kept");
    assert.equal(await sendRecover(env, email, "198.51.100.85"), 0, "no job during the cooldown");
    assert.equal(calls.resend.length, 0);
  }

  // Store budget used up: 429 with Retry-After: 10 before any cooldown record is written.
  {
    const email = "busy@example.com";
    const { env, calls } = makeRecoveryEnv(privB64, {});
    __exhaustStoreBudgetForTests(env);
    const w = makeWaitUntilCtx();
    const r = await worker.fetch(makeRecoverRequest(email, "198.51.100.86"), env, w.ctx);
    assert.equal(r.status, 429);
    assert.equal(r.headers.get("Retry-After"), "10");
    assert.deepEqual(await r.json(), { error: "rate_limited" });
    assert.equal(w.count(), 0);
    assert.equal(env.SEAT_DO.get(await recoverDoNameForTest(email))._hasSchema(), false, "no recover: record exists");
    assert.equal(calls.stripe.length + calls.resend.length, 0);
  }
});

test("23e. recover: 501 recovery_unconfigured without RESEND_API_KEY / RECEIPT_FROM_EMAIL / STRIPE_SECRET_KEY, 400 on malformed email, 429 after 3 requests per 10 min per IP, 403 on cross-site Origin", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();

  for (const missing of ["RESEND_API_KEY", "RECEIPT_FROM_EMAIL", "STRIPE_SECRET_KEY"]) {
    const { env, calls } = makeRecoveryEnv(privB64, {});
    delete env[missing];
    const r = await worker.fetch(makeRecoverRequest("buyer@example.com", "198.51.100.70"), env, makeWaitUntilCtx().ctx);
    assert.equal(r.status, 501, `missing ${missing}`);
    assert.deepEqual(await r.json(), { error: "recovery_unconfigured" });
    assert.equal(calls.stripe.length + calls.resend.length, 0);
  }

  const { env, calls } = makeRecoveryEnv(privB64, {});
  const badEmails = [
    "", "a@b", "@example.com", "user@", "user@example", "user@@example.com", "two words@example.com",
    "user@example.com\r\nbcc: x@y.z", "user@.com", "user@example.", "a".repeat(250) + "@x.io", 42, null,
  ];
  for (const bad of badEmails) {
    const r = await worker.fetch(makeRecoverRequest(bad, "198.51.100.71"), env, makeWaitUntilCtx().ctx);
    assert.equal(r.status, 400, `expected 400 for ${JSON.stringify(bad)}`);
    assert.equal((await r.json()).error, "invalid_params");
  }
  assert.equal(calls.stripe.length, 0, "invalid emails never reach Stripe");
  // No seat is required on recovery requests (body had no seat field), and malformed emails do not consume the IP budget

  for (let i = 0; i < 3; i++) {
    const r = await worker.fetch(makeRecoverRequest(`flood${i}@example.com`, "198.51.100.72"), env, makeWaitUntilCtx().ctx);
    assert.equal(r.status, 200);
  }
  const r4 = await worker.fetch(makeRecoverRequest("flood3@example.com", "198.51.100.72"), env, makeWaitUntilCtx().ctx);
  assert.equal(r4.status, 429);
  assert.equal(r4.headers.get("Retry-After"), "60");
  // The recovery budget is separate from activation / claim budgets on the same IP
  assert.equal((await worker.fetch(makeClaimCheckoutRequest("chk_0123456789abcdef0123456789abcdef", "1111222233334444", { ip: "198.51.100.72" }), env)).status, 202);

  const csrf = await worker.fetch(makeRecoverRequest("buyer@example.com", "198.51.100.73", { Origin: "https://evil.example" }), env, makeWaitUntilCtx().ctx);
  assert.equal(csrf.status, 403);
  assert.equal((await csrf.json()).error, "forbidden_origin");
});

test("23f. /thank-you expired state shows the in-app recovery hint only when recovery is configured, and never when the key is still shown", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_thankYouRecoverHintSession00000047";
  const nowSec = Math.floor(Date.now() / 1000);
  const mk = (configured, old) => {
    let env;
    const doBinding = createSQLiteDOHarness(() => env);
    env = {
      ENVIRONMENT: "test",
      APP_NAME: "SampleApp",
      ED25519_PKCS8_B64: privB64,
      STRIPE_SECRET_KEY: "sk_live_mock_secret",
      SEAT_DO: doBinding,
      __TEST_FETCH: async () =>
        new Response(JSON.stringify({ ...PAID_SESSION_JSON, created: old ? nowSec - 7200 : nowSec - 30 }), { status: 200 }),
    };
    if (configured) {
      env.RESEND_API_KEY = "re_test";
      env.RECEIPT_FROM_EMAIL = "SampleApp <keys@sampleapp.example>";
    }
    return env;
  };
  const page = async (env, ip) => {
    __resetIsolateStateForTests(env); // each case verifies with Stripe afresh instead of reusing the 45s recent-valid cache
    return (await worker.fetch(new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": ip } }), env)).text();
  };

  const expiredConfigured = await page(mk(true, true), "198.51.100.80");
  assert.match(expiredConfigured, /id="recoverHint"/);
  assert.match(expiredConfigured, /click Email Key/);
  assert.doesNotMatch(expiredConfigured, /<form|fetch\(/, "no in-page POST: the endpoint rejects browser Origin headers by design");

  assert.doesNotMatch(await page(mk(false, true), "198.51.100.81"), /id="recoverHint"/);
  assert.doesNotMatch(await page(mk(true, false), "198.51.100.82"), /id="recoverHint"/);
});


test("25. HTML email rendering escapes APP_NAME and formats key + deep-link button", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const email = "html-escape@example.com";
  const key = "cs_live_recoverHtmlEscapeSession000000050";
  const { env, calls } = makeRecoveryEnv(privB64, { [email]: [paidSession(key, email)] }, { APP_NAME: "Test<App>&Co" });
  const { ctx, flush } = makeWaitUntilCtx();

  const res = await worker.fetch(makeRecoverRequest(email), env, ctx);
  assert.equal(res.status, 200);
  await flush();

  assert.equal(calls.resend.length, 1);
  const { html, text } = calls.resend[0].body;
  assert.ok(html.includes("Test&lt;App&gt;&amp;Co"), "APP_NAME is HTML-escaped in body and button");
  assert.equal(html.includes("<App>"), false, "no raw angle brackets from APP_NAME");
  assert.ok(html.includes(`<a href="https://activate.example.com/open#key=${key}"`));
  assert.ok(text.includes(key));
});

test("45. email buttons honor an https ACTIVATION_PAGE_URL, and GET /open serves a static page that keeps the key in the fragment", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const email = "open-page@example.com";
  const key = "cs_live_recoverOpenPageSession00000000051";

  // A configured https page wins; query strings on it are dropped so the key is never in a query.
  const cfg = makeRecoveryEnv(privB64, { [email]: [paidSession(key, email)] }, { ACTIVATION_PAGE_URL: "https://sampleapp.example/activate?x=1" });
  const run1 = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest(email), cfg.env, run1.ctx)).status, 200);
  await run1.flush();
  assert.ok(cfg.calls.resend[0].body.html.includes(`<a href="https://sampleapp.example/activate#key=${key}"`));

  // A non-https value is ignored and the Worker's own /open page is used.
  const email2 = "open-page-2@example.com";
  const bad = makeRecoveryEnv(privB64, { [email2]: [paidSession(key, email2)] }, { ACTIVATION_PAGE_URL: "sampleapp://x" });
  const run2 = makeWaitUntilCtx();
  assert.equal((await worker.fetch(makeRecoverRequest(email2), bad.env, run2.ctx)).status, 200);
  await run2.flush();
  assert.ok(bad.calls.resend[0].body.html.includes(`<a href="https://activate.example.com/open#key=${key}"`));

  // GET /open: no key in the server response, nonce CSP, no caching; other methods are refused.
  const res = await worker.fetch(new Request("https://activate.example.com/open"), cfg.env);
  assert.equal(res.status, 200);
  const page = await res.text();
  assert.equal(page.includes("cs_live_"), false);
  assert.ok(page.includes("location.hash"));
  assert.match(res.headers.get("Content-Security-Policy"), /script-src 'nonce-[A-Za-z0-9_-]+'/);
  assert.equal(res.headers.get("Cache-Control"), "no-store");
  const post = await worker.fetch(new Request("https://activate.example.com/open", { method: "POST" }), cfg.env);
  assert.equal(post.status, 405);
});

function readReleaseLog(stub) {
  const rows = stub.sql.exec(`SELECT value FROM meta WHERE key = 'release_log'`).toArray();
  return rows.length ? JSON.parse(rows[0].value) : [];
}

test("26a. release budget", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_releaseBudgetDefault00000000000026";
  const env = makePaidEnv(privB64);
  const ip = "198.51.100.26";
  const A = "1111222233334444";
  const B = "5555666677778888";
  const C = "9999aaaabbbbcccc";
  const D = "ddddeeeeffff0000";

  const a1 = await activateAndGetTicket(env, key, A, ip);
  await activateAndGetTicket(env, key, B, ip);
  assert.equal((await worker.fetch(makeDeactivateRequest(key, A, a1.ticket, ip), env)).status, 200);
  const c1 = await activateAndGetTicket(env, key, C, ip);
  assert.equal((await worker.fetch(makeDeactivateRequest(key, C, c1.ticket, ip), env)).status, 200);
  const a2 = await activateAndGetTicket(env, key, A, ip);

  const over = await worker.fetch(makeDeactivateRequest(key, A, a2.ticket, ip), env);
  assert.equal(over.status, 429);
  assert.equal(over.headers.get("Retry-After"), null);
  const overBody = await over.json();
  assert.equal(overBody.error, "release_limit");
  assert.ok(Number.isInteger(overBody.retryAfterSec));
  assert.ok(overBody.retryAfterSec >= 1 && overBody.retryAfterSec <= 31_536_000);

  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const rowA = stub.sql.exec(`SELECT deactivated_at FROM seats WHERE seat = ?`, A).toArray()[0];
  assert.equal(rowA.deactivated_at, null);

  assert.equal((await worker.fetch(makeActivateRequest(key, D, ip), env)).status, 409);
  const a3 = await activateAndGetTicket(env, key, A, ip);

  const nowSec = Math.floor(Date.now() / 1000);
  const stale = readReleaseLog(stub).map(() => nowSec - 366 * 86_400);
  stub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('release_log', ?)`, JSON.stringify(stale));
  assert.equal((await worker.fetch(makeDeactivateRequest(key, A, a3.ticket, ip), env)).status, 200);
});

test("26b. SEAT_RELEASES_PER_YEAR parsing", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const A = "1111222233334444";

  // "0": no release allowed at all.
  const keyZero = "cs_live_releaseBudgetZero000000000000000027";
  const envZero = makePaidEnv(privB64, { SEAT_RELEASES_PER_YEAR: "0" });
  const z = await activateAndGetTicket(envZero, keyZero, A, "198.51.100.27");
  const dz = await worker.fetch(makeDeactivateRequest(keyZero, A, z.ticket, "198.51.100.27"), envZero);
  assert.equal(dz.status, 429);
  const dzBody = await dz.json();
  assert.equal(dzBody.error, "release_limit");
  assert.equal(dzBody.retryAfterSec, 31_536_000);

  // "abc" and "65" fall back to MAX_SEATS (here 1, so the second release is refused).
  for (const [i, raw] of ["abc", "65"].entries()) {
    const key = `cs_live_releaseBudgetFallback${i}0000000000028`;
    const ip = `198.51.100.${28 + i}`;
    const env = makePaidEnv(privB64, { SEAT_RELEASES_PER_YEAR: raw, MAX_SEATS: "1" });
    const t1 = await activateAndGetTicket(env, key, A, ip);
    assert.equal((await worker.fetch(makeDeactivateRequest(key, A, t1.ticket, ip), env)).status, 200);
    const t2 = await activateAndGetTicket(env, key, A, ip);
    const d2 = await worker.fetch(makeDeactivateRequest(key, A, t2.ticket, ip), env);
    assert.equal(d2.status, 429, `SEAT_RELEASES_PER_YEAR=${raw}`);
    assert.equal((await d2.json()).error, "release_limit");
  }

  // Deactivating a seat that is not active is a 200 no-op and does not spend the budget.
  const keyNoop = "cs_live_releaseBudgetNoop000000000000000030";
  const ipNoop = "198.51.100.30";
  const envNoop = makePaidEnv(privB64);
  const n = await activateAndGetTicket(envNoop, keyNoop, A, ipNoop);
  assert.equal((await worker.fetch(makeDeactivateRequest(keyNoop, A, n.ticket, ipNoop), envNoop)).status, 200);
  const stub = envNoop.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + keyNoop)));
  const logBefore = readReleaseLog(stub);
  assert.equal(logBefore.length, 1);
  assert.equal((await worker.fetch(makeDeactivateRequest(keyNoop, A, n.ticket, ipNoop), envNoop)).status, 200);
  assert.deepEqual(readReleaseLog(stub), logBefore);
});

function ticketIssued(ticket) {
  return Number(Buffer.from(ticket.slice(4).split(".")[0], "base64url").toString("utf8").split("|")[2]);
}

test("27. minIssued", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const sessionKey = "cs_live_minIssuedFloorSession0000000000031";
  const handoff = "chk_27272727272727272727272727272727";
  const seat = "1111222233334444";
  const ip = "198.51.100.31";
  const nowSec = Math.floor(Date.now() / 1000);

  let env;
  const doBinding = createSQLiteDOHarness(() => env);
  env = {
    ENVIRONMENT: "test",
    ED25519_PKCS8_B64: privB64,
    STRIPE_SECRET_KEY: "sk_live_mock_secret",
    SEAT_DO: doBinding,
    __TEST_FETCH: async () =>
      new Response(
        JSON.stringify({ ...PAID_SESSION_JSON, id: sessionKey, created: nowSec - 15, client_reference_id: handoff }),
        { status: 200 }
      ),
  };

  const cases = [
    [nowSec + 1000, (issued) => issued === nowSec + 1000],
    [nowSec + 400 * 86_400, (issued) => Math.abs(issued - (nowSec + 366 * 86_400)) <= 5],
    [-1, (issued) => Math.abs(issued - nowSec) <= 5],
    [1.5, (issued) => Math.abs(issued - nowSec) <= 5],
    ["123", (issued) => Math.abs(issued - nowSec) <= 5],
    [2 ** 53, (issued) => Math.abs(issued - nowSec) <= 5],
  ];

  for (const [minIssued, ok] of cases) {
    const res = await worker.fetch(makePostRequest({ action: "activate", key: sessionKey, seat, minIssued }, ip), env);
    assert.equal(res.status, 200, `activate minIssued=${minIssued}`);
    const issued = ticketIssued((await res.json()).ticket);
    assert.ok(ok(issued), `activate minIssued=${minIssued} -> issued=${issued}`);
  }

  const thankYou = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${sessionKey}`, { headers: { "CF-Connecting-IP": ip } }),
    env
  );
  assert.equal(thankYou.status, 200);

  for (const [minIssued, ok] of cases) {
    const res = await worker.fetch(makePostRequest({ action: "claim_checkout", handoff, seat, minIssued }, ip), env);
    assert.equal(res.status, 200, `claim_checkout minIssued=${minIssued}`);
    const issued = ticketIssued((await res.json()).ticket);
    assert.ok(ok(issued), `claim_checkout minIssued=${minIssued} -> issued=${issued}`);
  }
});

test("30. existing seats and upstream doubt", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_existingSeatUpstreamDoubt00000032";
  const seat = "1111222233334444";
  let stripeDown = false;
  const env = makePaidEnv(privB64, {
    __TEST_FETCH: async () =>
      stripeDown
        ? new Response(JSON.stringify({ error: { message: "unavailable" } }), { status: 503 })
        : new Response(JSON.stringify(PAID_SESSION_JSON), { status: 200 }),
  });
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const setVerifiedAt = (ms) => stub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('verified_at', ?)`, String(ms));
  const readVerifiedAt = () => stub.sql.exec(`SELECT value FROM meta WHERE key = 'verified_at'`).toArray()[0]?.value;

  // (a) Stripe outage, last successful check two hours ago: re-mint, verified_at unchanged.
  await activateAndGetTicket(env, key, seat, "198.51.100.32");
  const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
  setVerifiedAt(twoHoursAgo);
  stripeDown = true;
  const a = await worker.fetch(makeActivateRequest(key, seat, "198.51.100.32"), env);
  assert.equal(a.status, 200);
  assert.ok((await a.json()).ticket.startsWith("LK1-"));
  assert.equal(readVerifiedAt(), String(twoHoursAgo));

  // (b) Stripe outage, last successful check 31 days ago: 502, record kept.
  setVerifiedAt(Date.now() - 31 * 86_400_000);
  const b = await worker.fetch(makeActivateRequest(key, seat, "198.51.100.32"), env);
  assert.equal(b.status, 502);
  assert.equal((await b.json()).error, "upstream_unavailable");
  const active = stub.sql.exec(`SELECT seat FROM seats WHERE deactivated_at IS NULL`).toArray();
  assert.equal(active.length, 1);

  // (c) Store budget exhausted: an existing seat due for re-verification gets 429 rate_limited.
  stripeDown = false;
  setVerifiedAt(twoHoursAgo);
  for (let i = 0; i < 40; i++) {
    const ip = `198.51.100.${40 + Math.floor(i / 10)}`;
    const k = `cs_live_storeBudgetExhaust${String(i).padStart(4, "0")}00000000`;
    await worker.fetch(makeActivateRequest(k, "5555666677778888", ip), env);
  }
  const c = await worker.fetch(makeActivateRequest(key, seat, "198.51.100.49"), env);
  assert.equal(c.status, 429);
  assert.equal(c.headers.get("Retry-After"), "10");
  assert.equal((await c.json()).error, "rate_limited");
});

test("31. thank-you script", async () => {
  const vm = await import("node:vm");
  const { privB64 } = await generateEd25519KeyPairB64();
  const freshKey = "cs_live_thankYouScriptFreshSession000000031";
  const staleKey = "cs_live_thankYouScriptStaleSession000000031";
  const env = makePaidEnv(privB64, {
    APP_NAME: "A</script><b>&",
    __TEST_FETCH: async (url) => {
      const stale = String(url).includes(staleKey);
      return new Response(
        JSON.stringify({ ...PAID_SESSION_JSON, created: Math.floor(Date.now() / 1000) - (stale ? 2 * 3600 : 10) }),
        { status: 200 }
      );
    },
  });
  const page = async (key, ip) => {
    const res = await worker.fetch(new Request(`https://activate.example.com/thank-you?session_id=${key}`, { headers: { "CF-Connecting-IP": ip } }), env);
    assert.equal(res.status, 200);
    return res.text();
  };
  const tagFor = async (key) => (await sha256HexTest("seatstamp-key-v1|" + key)).slice(0, 16).toUpperCase();

  const freshHtml = await page(freshKey, "198.51.100.81");
  const freshTag = await tagFor(freshKey);
  assert.equal(freshHtml.split("</script>").length - 1, 1);
  assert.ok(freshHtml.includes("\\u003c/script\\u003e"));
  assert.ok(freshHtml.includes("clearBtn"));
  assert.ok(freshHtml.includes('"seatstamp_backup_key_"'));
  assert.ok(freshHtml.includes('var scheme = "myapp";'));
  assert.ok(freshHtml.includes(`var orderTag = "${freshTag}";`));

  const staleHtml = await page(staleKey, "198.51.100.82");
  const staleTag = await tagFor(staleKey);
  assert.ok(!staleHtml.includes(staleKey));

  const runScript = (html, { store = new Map(), search = "" } = {}) => {
    const body = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)[1];
    const elements = new Map();
    const getEl = (id) => {
      if (!elements.has(id)) {
        elements.set(id, {
          textContent: "",
          attrs: {},
          handlers: {},
          removed: false,
          setAttribute(k, v) { this.attrs[k] = v; },
          addEventListener(type, fn) { this.handlers[type] = fn; },
          remove() { this.removed = true; },
        });
      }
      return elements.get(id);
    };
    const context = vm.createContext({
      localStorage: {
        getItem: (k) => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: (k) => store.delete(k),
      },
      document: { getElementById: getEl },
      location: { search },
      navigator: { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      URLSearchParams,
      setTimeout,
      Blob,
      URL,
    });
    vm.runInContext(body, context);
    return { store, el: getEl };
  };
  const slotFor = (tag) => `seatstamp_backup_key_myapp_${tag}`;

  // (a) server key present: one per-order slot holding { k, t }
  const a = runScript(freshHtml);
  assert.deepEqual([...a.store.keys()], [slotFor(freshTag)]);
  const saved = JSON.parse(a.store.get(slotFor(freshTag)));
  assert.equal(saved.k, freshKey);
  assert.equal(typeof saved.t, "number");

  // (e) the Clear button removes the slot
  a.el("clearBtn").handlers.click();
  assert.equal(a.store.has(slotFor(staleTag)), false);
  assert.equal(a.store.has(slotFor(freshTag)), false);
  assert.equal(a.el("licKey").textContent, "Saved key cleared from this browser.");
  assert.equal(a.el("activateBtn").attrs.href, "myapp://activate");
  assert.equal(a.el("clearBtn").textContent, "Cleared");

  // (b) no server key and a 31-day-old slot: not shown, slot removed
  const old = new Map([[slotFor(staleTag), JSON.stringify({ k: staleKey, t: Date.now() - 31 * 86_400_000 })]]);
  const b = runScript(staleHtml, { store: old, search: `?session_id=${staleKey}` });
  assert.notEqual(b.el("licKey").textContent, staleKey);
  assert.equal(b.store.has(slotFor(staleTag)), false);
});

test("32. pending payments", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const modes = new Map();
  const calls = new Map();
  const sessionFor = (mode) => {
    const json = structuredClone(PAID_SESSION_JSON);
    json.created = Math.floor(Date.now() / 1000) - 10;
    if (mode === "open") {
      json.status = "open";
      json.payment_status = "unpaid";
      json.payment_intent = null;
    } else if (mode === "unpaid") {
      json.status = "complete";
      json.payment_status = "unpaid";
      json.payment_intent = null;
    } else if (mode === "expired") {
      json.status = "expired";
      json.payment_status = "unpaid";
      json.payment_intent = null;
    }
    return json;
  };
  const env = makePaidEnv(privB64, {
    __TEST_FETCH: async (url) => {
      const id = decodeURIComponent(String(url).split("/v1/checkout/sessions/")[1].split("?")[0]);
      calls.set(id, (calls.get(id) || 0) + 1);
      return new Response(JSON.stringify(sessionFor(modes.get(id) || "paid")), { status: 200 });
    },
  });
  const ip = "198.51.100.91";
  const seat = "1111222233334444";

  // (a) open session, (b) complete but unpaid: 409 payment_pending, then 200 once paid, with no negative cache
  for (const [mode, key] of [
    ["open", "cs_live_pendingPaymentOpenSession0000000a"],
    ["unpaid", "cs_live_pendingPaymentUnpaidSession00000b"],
  ]) {
    modes.set(key, mode);
    const pending = await worker.fetch(makeActivateRequest(key, seat, ip), env);
    assert.equal(pending.status, 409, mode);
    assert.equal(pending.headers.get("Retry-After"), "10");
    assert.deepEqual(await pending.json(), { error: "payment_pending" });
    const callsBefore = calls.get(key);
    modes.set(key, "paid");
    const paid = await worker.fetch(makeActivateRequest(key, seat, ip), env);
    assert.equal(paid.status, 200, mode);
    assert.ok(calls.get(key) > callsBefore);
  }

  // (c) expired session: 403 invalid_key and negative-cached
  const expiredKey = "cs_live_pendingPaymentExpiredSession0000c";
  modes.set(expiredKey, "expired");
  const expired = await worker.fetch(makeActivateRequest(expiredKey, seat, ip), env);
  assert.equal(expired.status, 403);
  assert.equal((await expired.json()).error, "invalid_key");
  const expiredCalls = calls.get(expiredKey);
  assert.equal((await worker.fetch(makeActivateRequest(expiredKey, seat, ip), env)).status, 403);
  assert.equal(calls.get(expiredKey), expiredCalls);

  // (d) /thank-you for an open session
  const openPageKey = "cs_live_pendingPaymentThankYouPage00000d";
  modes.set(openPageKey, "open");
  const page = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${openPageKey}`, { headers: { "CF-Connecting-IP": ip } }),
    env
  );
  assert.equal(page.status, 202);
  assert.equal(page.headers.get("Retry-After"), "10");
  assert.equal(await page.text(), "Your payment is still processing. Reload this page in a moment.");

  // (e) an existing record answered with an open session is not wiped
  const existingKey = "cs_live_pendingPaymentExistingRecord000e";
  await activateAndGetTicket(env, existingKey, seat, ip);
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + existingKey)));
  stub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('verified_at', ?)`, String(Date.now() - 2 * 3600 * 1000));
  modes.set(existingKey, "open");
  const existing = await worker.fetch(makeActivateRequest(existingKey, seat, ip), env);
  assert.equal(existing.status, 409);
  assert.equal((await existing.json()).error, "payment_pending");
  assert.equal(stub._hasSchema(), true);
  assert.deepEqual(stub._readRecord().seats, [seat]);

  // (f) claim_checkout while the session is open answers 202 pending, then 200 once paid
  const claimKey = "cs_live_pendingPaymentClaimSession00000f";
  const handoff = "chk_f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
  modes.set(claimKey, "open");
  const handoffStub = env.SEAT_DO.get("handoff:" + (await sha256HexTest("seatstamp-key-v1|handoff|" + handoff)));
  await handoffStub.recordCheckoutHandoff({ sessionId: claimKey, nowMs: Date.now() });
  const claimPending = await worker.fetch(makeClaimCheckoutRequest(handoff, seat, { ip }), env);
  assert.equal(claimPending.status, 202);
  assert.deepEqual(await claimPending.json(), { status: "pending" });
  modes.set(claimKey, "paid");
  const claimPaid = await worker.fetch(makeClaimCheckoutRequest(handoff, seat, { ip }), env);
  assert.equal(claimPaid.status, 200);
  assert.equal((await claimPaid.json()).key, claimKey);
});

test("35. disputes", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const disputesByPi = new Map(); // pi id -> array of dispute statuses, or a number for an HTTP error status
  const refundedPis = new Set();
  const disputeRequests = [];
  const env = makePaidEnv(privB64, {
    __TEST_FETCH: async (url, init) => {
      const u = new URL(String(url));
      if (String(url).startsWith("https://api.stripe.com/v1/disputes?")) {
        disputeRequests.push({ url: String(url), version: init.headers["Stripe-Version"] });
        const conf = disputesByPi.get(u.searchParams.get("payment_intent"));
        if (typeof conf === "number") return new Response(JSON.stringify({ error: { message: "mock" } }), { status: conf });
        const data = (conf || []).map((status, i) => ({ id: `dp_${i}`, object: "dispute", status }));
        return new Response(JSON.stringify({ object: "list", data, has_more: false }), { status: 200 });
      }
      const id = decodeURIComponent(u.pathname.split("/v1/checkout/sessions/")[1]);
      const pi = "pi_" + id.slice(-12);
      const json = structuredClone(PAID_SESSION_JSON);
      json.created = Math.floor(Date.now() / 1000) - 10;
      json.payment_intent.id = pi;
      json.payment_intent.latest_charge.disputed = true;
      if (refundedPis.has(pi)) {
        json.payment_intent.latest_charge.refunded = true;
        json.payment_intent.latest_charge.amount_refunded = 900;
      }
      return new Response(JSON.stringify(json), { status: 200 });
    },
  });
  const piFor = (key) => "pi_" + key.slice(-12);
  const stubFor = async (key) => env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const seatA = "1111222233334444";
  const seatB = "5555666677778888";
  const activate = (key, seat, ip) => worker.fetch(makeActivateRequest(key, seat, ip), env);

  // (a) won -> 200 with a ticket
  const wonKey = "cs_live_disputeWonSession00000000000035a";
  disputesByPi.set(piFor(wonKey), ["won"]);
  const a = await activate(wonKey, seatA, "198.51.100.110");
  assert.equal(a.status, 200);
  assert.ok((await a.json()).ticket.startsWith("LK1-"));

  // (b) warning_closed -> 200
  const closedKey = "cs_live_disputeWarningClosed00000000035b";
  disputesByPi.set(piFor(closedKey), ["warning_closed"]);
  assert.equal((await activate(closedKey, seatA, "198.51.100.111")).status, 200);

  // (c) won plus lost -> 403 invalid_key and the record is wiped
  const lostKey = "cs_live_disputeWonPlusLost000000000035c";
  disputesByPi.set(piFor(lostKey), ["won"]);
  await activateAndGetTicket(env, lostKey, seatA, "198.51.100.112");
  const lostStub = await stubFor(lostKey);
  assert.equal(lostStub._hasSchema(), true);
  disputesByPi.set(piFor(lostKey), ["won", "lost"]);
  const c = await activate(lostKey, seatB, "198.51.100.112");
  assert.equal(c.status, 403);
  assert.deepEqual(await c.json(), { error: "invalid_key" });
  assert.equal(lostStub._hasSchema(), false);

  // (d) prevented -> 403 invalid_key
  const preventedKey = "cs_live_disputePreventedSession0000035d";
  disputesByPi.set(piFor(preventedKey), ["prevented"]);
  const d = await activate(preventedKey, seatA, "198.51.100.113");
  assert.equal(d.status, 403);
  assert.deepEqual(await d.json(), { error: "invalid_key" });

  // (e) needs_response: a new seat gets 403 payment_disputed, nothing is wiped or cached
  const openKey = "cs_live_disputeNeedsResponse00000000035e";
  disputesByPi.set(piFor(openKey), ["won"]);
  await activateAndGetTicket(env, openKey, seatA, "198.51.100.114");
  const openStub = await stubFor(openKey);
  disputesByPi.set(piFor(openKey), ["needs_response"]);
  const e1 = await activate(openKey, seatB, "198.51.100.114");
  assert.equal(e1.status, 403);
  assert.deepEqual(await e1.json(), { error: "payment_disputed" });
  assert.equal(openStub._hasSchema(), true);
  assert.deepEqual(openStub._readRecord().seats, [seatA]);
  disputesByPi.set(piFor(openKey), ["won"]);
  const e2 = await activate(openKey, seatB, "198.51.100.114");
  assert.equal(e2.status, 200);

  // (f) under_review for an existing seat verified two hours ago -> 200, verified_at unchanged
  const reviewKey = "cs_live_disputeUnderReviewExisting0035f";
  disputesByPi.set(piFor(reviewKey), ["won"]);
  await activateAndGetTicket(env, reviewKey, seatA, "198.51.100.115");
  const reviewStub = await stubFor(reviewKey);
  const twoHoursAgo = String(Date.now() - 2 * 3600 * 1000);
  reviewStub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('verified_at', ?)`, twoHoursAgo);
  disputesByPi.set(piFor(reviewKey), ["under_review"]);
  const f = await activate(reviewKey, seatA, "198.51.100.115");
  assert.equal(f.status, 200);
  assert.equal(reviewStub.sql.exec(`SELECT value FROM meta WHERE key = 'verified_at'`).toArray()[0]?.value, twoHoursAgo);

  // (g) the disputes call answering 403 -> 502 upstream_unavailable
  const forbiddenKey = "cs_live_disputeListForbidden00000000035g";
  disputesByPi.set(piFor(forbiddenKey), 403);
  const g = await activate(forbiddenKey, seatA, "198.51.100.116");
  assert.equal(g.status, 502);
  assert.deepEqual(await g.json(), { error: "upstream_unavailable" });

  // (h) refunded and disputed -> 403 without any disputes request
  const refundedKey = "cs_live_disputeRefundedAndDisputed0035h";
  refundedPis.add(piFor(refundedKey));
  disputesByPi.set(piFor(refundedKey), ["won"]);
  const requestsBefore = disputeRequests.length;
  const h = await activate(refundedKey, seatA, "198.51.100.117");
  assert.equal(h.status, 403);
  assert.equal(disputeRequests.length, requestsBefore);

  // (i) every disputes request is scoped to the PaymentIntent, asks for 100, and pins the API version
  assert.ok(disputeRequests.length > 0);
  for (const req of disputeRequests) {
    assert.ok(req.url.includes("payment_intent=pi_"), req.url);
    assert.ok(req.url.includes("limit=100"), req.url);
    assert.equal(req.version, "2026-10-28.endive");
  }

  // (j) /thank-you for an open dispute
  const pageKey = "cs_live_disputeThankYouOpenDispute0035j";
  disputesByPi.set(piFor(pageKey), ["warning_under_review"]);
  const page = await worker.fetch(
    new Request(`https://activate.example.com/thank-you?session_id=${pageKey}`, { headers: { "CF-Connecting-IP": "198.51.100.118" } }),
    env
  );
  assert.equal(page.status, 403);
  assert.equal(await page.text(), "This payment is under dispute. Contact the seller.");
});

test("36. Stripe version and unexpected statuses", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const versions = { retrieve: [], fallbackList: [], recoveryList: [] };
  const retrieveStatus = new Map();
  const retrieveCalls = new Map();
  let fallbackListStatus = 200;
  const env = makePaidEnv(privB64, {
    RESEND_API_KEY: "re_test_mock_key",
    RECEIPT_FROM_EMAIL: "SampleApp <keys@sampleapp.example>",
    __TEST_FETCH: async (url, init) => {
      const u = new URL(String(url));
      if (u.hostname === "api.resend.com") return new Response(JSON.stringify({ id: "email_x" }), { status: 200 });
      const single = /\/v1\/checkout\/sessions\/(cs_[A-Za-z0-9_]+)$/.exec(u.pathname);
      if (single) {
        const id = single[1];
        versions.retrieve.push(init.headers["Stripe-Version"]);
        retrieveCalls.set(id, (retrieveCalls.get(id) || 0) + 1);
        const status = retrieveStatus.get(id) || 200;
        if (status !== 200) return new Response(JSON.stringify({ error: { message: "mock" } }), { status });
        return new Response(JSON.stringify(PAID_SESSION_JSON), { status: 200 });
      }
      if (u.searchParams.has("customer_details[email]")) {
        versions.recoveryList.push(init.headers["Stripe-Version"]);
        return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
      }
      versions.fallbackList.push(init.headers["Stripe-Version"]);
      if (fallbackListStatus !== 200) {
        return new Response(JSON.stringify({ error: { message: "mock" } }), { status: fallbackListStatus });
      }
      return new Response(JSON.stringify({ object: "list", data: [], has_more: false }), { status: 200 });
    },
  });
  const seatA = "1111222233334444";
  const seatB = "5555666677778888";

  // (b) an unexpected 400 on the session retrieve fails closed without wiping or negative-caching
  const key = "cs_live_unexpectedStripeStatus0000000036";
  await activateAndGetTicket(env, key, seatA, "198.51.100.101");
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  stub.sql.exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('verified_at', ?)`, String(Date.now() - 2 * 3600 * 1000));
  retrieveStatus.set(key, 400);
  const existing = await worker.fetch(makeActivateRequest(key, seatA, "198.51.100.101"), env);
  assert.equal(existing.status, 200);
  assert.ok((await existing.json()).ticket.startsWith("LK1-"));
  const fresh = await worker.fetch(makeActivateRequest(key, seatB, "198.51.100.101"), env);
  assert.equal(fresh.status, 502);
  assert.equal((await fresh.json()).error, "upstream_unavailable");
  assert.equal(stub._hasSchema(), true);
  assert.deepEqual(stub._readRecord().seats, [seatA]);
  const callsBefore = retrieveCalls.get(key);
  const again = await worker.fetch(makeActivateRequest(key, seatB, "198.51.100.101"), env);
  assert.equal(again.status, 502);
  assert.ok(retrieveCalls.get(key) > callsBefore, "a 400 is not negative-cached");

  // (c) a 404 is still a definite invalid answer: 403, wipe, negative cache
  const goneKey = "cs_live_unexpectedStripeStatusGone000036";
  await activateAndGetTicket(env, goneKey, seatA, "198.51.100.102");
  const goneStub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + goneKey)));
  assert.equal(goneStub._hasSchema(), true);
  retrieveStatus.set(goneKey, 404);
  const gone = await worker.fetch(makeActivateRequest(goneKey, seatB, "198.51.100.102"), env);
  assert.equal(gone.status, 403);
  assert.deepEqual(await gone.json(), { error: "invalid_key" });
  assert.equal(goneStub._hasSchema(), false);
  const goneCalls = retrieveCalls.get(goneKey);
  assert.equal((await worker.fetch(makeActivateRequest(goneKey, seatB, "198.51.100.102"), env)).status, 403);
  assert.equal(retrieveCalls.get(goneKey), goneCalls);

  // (d) a 400 on the fallback list call gives 502 upstream_unavailable, not 202 pending
  fallbackListStatus = 400;
  await seedHandoffFirstSeen(env, "chk_36363636363636363636363636363636", seatA);
  const claim = await worker.fetch(
    makeClaimCheckoutRequest("chk_36363636363636363636363636363636", seatA, { fallbackSearch: true, ip: "198.51.100.103" }),
    env
  );
  assert.equal(claim.status, 502);
  assert.deepEqual(await claim.json(), { error: "upstream_unavailable" });

  // recovery list call
  const { ctx, flush } = makeWaitUntilCtx();
  const rec = await worker.fetch(makeRecoverRequest("buyer36@example.com", "198.51.100.104"), env, ctx);
  assert.equal(rec.status, 200);
  await flush();

  // (a) every Stripe request carries the pinned version
  for (const [name, list] of Object.entries(versions)) {
    assert.ok(list.length > 0, name);
    for (const v of list) assert.equal(v, "2026-10-28.endive", name);
  }
});

test("37. deactivate accepts a ticket signed by a retired key listed in ED25519_RETIRED_PUB_B64", async () => {
  const key1 = await generateEd25519KeyPairB64();
  const key2 = await generateEd25519KeyPairB64();
  const key = "cs_live_retiredKeyDeactivate00000000037";
  const seat = "1111222233334444";
  const env = makePaidEnv(key1.privB64);

  const a1 = await activateAndGetTicket(env, key, seat, "198.51.100.137");

  // The Worker now signs with key 2 and does not list key 1 as retired.
  env.ED25519_PKCS8_B64 = key2.privB64;
  const refused = await worker.fetch(makeDeactivateRequest(key, seat, a1.ticket, "198.51.100.137"), env);
  assert.equal(refused.status, 403);
  assert.equal((await refused.json()).error, "invalid_ticket");

  env.ED25519_RETIRED_PUB_B64 = Buffer.from(key1.rawPub).toString("base64");
  const released = await worker.fetch(makeDeactivateRequest(key, seat, a1.ticket, "198.51.100.137"), env);
  assert.equal(released.status, 200);
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const rows = stub.sql.exec(`SELECT deactivated_at FROM seats WHERE seat = ?`, seat).toArray();
  assert.ok(Number(rows[0].deactivated_at) > 0);

  const a2 = await activateAndGetTicket(env, key, seat, "198.51.100.137");
  const [p, s] = a2.ticket.slice(4).split(".");
  const payload = Buffer.from(p, "base64url");
  const sig = Buffer.from(s, "base64url");
  assert.equal(await crypto.subtle.verify("Ed25519", key2.publicKey, sig, payload), true);
  assert.equal(await crypto.subtle.verify("Ed25519", key1.publicKey, sig, payload), false);
});

test("38. deactivate with a missing or malformed signing key returns 500 signing_error and keeps the seat", async () => {
  const good = await generateEd25519KeyPairB64();
  const other = await generateEd25519KeyPairB64();
  const key = "cs_live_signingKeyBrokenDeactivate000038";
  const seat = "1111222233334444";
  const ip = "198.51.100.138";
  const env = makePaidEnv(good.privB64);
  const a1 = await activateAndGetTicket(env, key, seat, ip);
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const seatActive = () =>
    stub.sql.exec(`SELECT deactivated_at FROM seats WHERE seat = ?`, seat).toArray()[0].deactivated_at === null;

  // (a) the signing key secret is missing
  delete env.ED25519_PKCS8_B64;
  const missing = await worker.fetch(makeDeactivateRequest(key, seat, a1.ticket, ip), env);
  assert.equal(missing.status, 500);
  assert.deepEqual(await missing.json(), { error: "signing_error" });
  assert.equal(seatActive(), true);

  // (b) a malformed public key override
  env.ED25519_PKCS8_B64 = good.privB64;
  env.ED25519_PUB_B64 = "AAAA";
  const malformed = await worker.fetch(makeDeactivateRequest(key, seat, a1.ticket, ip), env);
  assert.equal(malformed.status, 500);
  assert.deepEqual(await malformed.json(), { error: "signing_error" });

  // (c) a stale override: the public key of another key pair
  env.ED25519_PUB_B64 = Buffer.from(other.rawPub).toString("base64");
  const stale = await worker.fetch(makeDeactivateRequest(key, seat, a1.ticket, ip), env);
  assert.equal(stale.status, 500);
  assert.deepEqual(await stale.json(), { error: "signing_error" });
  assert.equal(seatActive(), true);

  // (d) a good env and a garbage ticket still give 403 invalid_ticket
  delete env.ED25519_PUB_B64;
  const garbage = await worker.fetch(makeDeactivateRequest(key, seat, "LK1-garbage.ticket", ip), env);
  assert.equal(garbage.status, 403);
  assert.deepEqual(await garbage.json(), { error: "invalid_ticket" });
  assert.equal(seatActive(), true);
});

test("39. unknown paths return 404 not_found; wrong methods return 405 with the right Allow header", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const env = makePaidEnv(privB64);

  const getNope = await worker.fetch(new Request("https://activate.example.com/nope", { method: "GET" }), env);
  assert.equal(getNope.status, 404);
  assert.deepEqual(await getNope.json(), { error: "not_found" });

  const postActivate = await worker.fetch(
    new Request("https://activate.example.com/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "activate", key: "cs_live_x", seat: "1111222233334444" }),
    }),
    env
  );
  assert.equal(postActivate.status, 404);
  assert.deepEqual(await postActivate.json(), { error: "not_found" });

  const getRoot = await worker.fetch(new Request("https://activate.example.com/", { method: "GET" }), env);
  assert.equal(getRoot.status, 405);
  assert.equal(getRoot.headers.get("Allow"), "POST");

  const postThankYou = await worker.fetch(new Request("https://activate.example.com/thank-you", { method: "POST" }), env);
  assert.equal(postThankYou.status, 405);
  assert.equal(postThankYou.headers.get("Allow"), "GET");

  const putSuccess = await worker.fetch(new Request("https://activate.example.com/success", { method: "PUT" }), env);
  assert.equal(putSuccess.status, 405);
  assert.equal(putSuccess.headers.get("Allow"), "GET");
});

test("40. optional POST_RATE_LIMITER binding", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_postRateLimiterBinding0000000040";

  // limit() answering success: false -> 429 rate_limited with Retry-After: 60, before the body is read
  const limitKeys = [];
  const envDenied = makePaidEnv(privB64, {
    POST_RATE_LIMITER: { async limit({ key }) { limitKeys.push(key); return { success: false }; } },
  });
  const denied = await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.130"), envDenied);
  assert.equal(denied.status, 429);
  assert.deepEqual(await denied.json(), { error: "rate_limited" });
  assert.equal(denied.headers.get("Retry-After"), "60");
  assert.equal(limitKeys.length, 1);
  assert.match(limitKeys[0], /^[0-9a-f]{32}$/);
  assert.equal(limitKeys[0].includes("198.51.100.130"), false, "the IP address is never passed in clear");
  const expected = (await sha256HexTest("seatstamp-key-v1|" + "rl|" + "198.51.100.130")).slice(0, 32);
  assert.equal(limitKeys[0], expected);

  // limit() that throws lets the request through
  const envThrows = makePaidEnv(privB64, {
    POST_RATE_LIMITER: { async limit() { throw new Error("binding down"); } },
  });
  assert.equal((await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.131"), envThrows)).status, 200);

  // limit() answering success: true lets the request through
  const envAllowed = makePaidEnv(privB64, { POST_RATE_LIMITER: { async limit() { return { success: true }; } } });
  assert.equal((await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.132"), envAllowed)).status, 200);

  // No binding lets the request through
  const envNone = makePaidEnv(privB64);
  assert.equal((await worker.fetch(makeActivateRequest(key, "1111222233334444", "198.51.100.133"), envNone)).status, 200);
});

async function seatPepperIdForTest(pepper, seat) {
  const hmacKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(seat)));
  return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

test("42. SEAT_PEPPER stores an HMAC instead of the seat code and migrates existing rows without using a seat", async () => {
  const { privB64, publicKey } = await generateEd25519KeyPairB64();
  const pepper = "test-pepper-0123456789abcdef0123456789";
  const ip = "198.51.100.142";
  const seatRows = async (env, key) =>
    env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)))
      .sql.exec(`SELECT seat, deactivated_at FROM seats ORDER BY seat`)
      .toArray();

  // (a) with the pepper set, the raw seat code never reaches SQLite
  const keyA = "cs_live_seatPepperStoresHmac0000000000042";
  const seatA = "1111222233334444";
  const envA = makePaidEnv(privB64, { SEAT_PEPPER: pepper });
  const a1 = await activateAndGetTicket(envA, keyA, seatA, ip);
  assert.equal(a1.seatsUsed, 1);
  const peppered = await seatPepperIdForTest(pepper, seatA);
  let rows = await seatRows(envA, keyA);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].seat, peppered);
  assert.equal(rows.some((r) => r.seat === seatA), false);
  const [p, s] = a1.ticket.slice(4).split(".");
  const payload = Buffer.from(p, "base64url");
  assert.equal(await crypto.subtle.verify("Ed25519", publicKey, Buffer.from(s, "base64url"), payload), true);
  assert.ok(payload.toString("utf8").endsWith("|" + seatA), "the ticket is bound to the raw seat code");
  // An active seat is recognized again and does not take a second seat
  const a1again = await activateAndGetTicket(envA, keyA, seatA, ip);
  assert.equal(a1again.seatsUsed, 1);
  const dA = await worker.fetch(makeDeactivateRequest(keyA, seatA, a1.ticket, ip), envA);
  assert.equal(dA.status, 200);
  rows = await seatRows(envA, keyA);
  assert.equal(rows.length, 1);
  assert.ok(Number(rows[0].deactivated_at) > 0);

  // (b) turning the pepper on migrates an existing row without using a second seat
  const keyB = "cs_live_seatPepperMigratesRow00000000042";
  const seatB = "5555666677778888";
  const envB = makePaidEnv(privB64);
  const b1 = await activateAndGetTicket(envB, keyB, seatB, ip);
  assert.equal(b1.seatsUsed, 1);
  assert.equal((await seatRows(envB, keyB))[0].seat, seatB);
  envB.SEAT_PEPPER = pepper;
  const b2 = await activateAndGetTicket(envB, keyB, seatB, ip);
  assert.equal(b2.seatsUsed, 1);
  rows = await seatRows(envB, keyB);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].seat, await seatPepperIdForTest(pepper, seatB));

  // A seat activated before the pepper was set can still deactivate after it is set
  const keyC = "cs_live_seatPepperLateDeactivate000000042";
  const seatC = "9999aaaabbbbcccc";
  const envC = makePaidEnv(privB64);
  const c1 = await activateAndGetTicket(envC, keyC, seatC, ip);
  envC.SEAT_PEPPER = pepper;
  const dC = await worker.fetch(makeDeactivateRequest(keyC, seatC, c1.ticket, ip), envC);
  assert.equal(dC.status, 200);
  rows = await seatRows(envC, keyC);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].seat, await seatPepperIdForTest(pepper, seatC));
  assert.ok(Number(rows[0].deactivated_at) > 0);
});

function makeEraseRequest(key, adminToken, ip, headers = {}) {
  return makePostRequest({ action: "erase", key, adminToken }, ip, headers);
}

test("43a. erase: admin-token gated, rate limited, wipes only the license record", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_eraseAdminTokenGated0000000000043";
  const otherKey = "cs_live_eraseUnrelatedRecord0000000000043";
  const seat = "1111222233334444";
  const token = "admin-token-0123456789abcdef0123456789abcdef";
  const env = makePaidEnv(privB64);
  const bodies = [];
  const send = async (req) => {
    const res = await worker.fetch(req, env);
    const text = await res.text();
    bodies.push(text);
    return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
  };

  await activateAndGetTicket(env, key, seat, "198.51.100.143");
  await activateAndGetTicket(env, otherKey, seat, "198.51.100.143");
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  const otherStub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + otherKey)));

  // (a) no token configured, or a token shorter than 32 characters
  let r = await send(makeEraseRequest(key, token, "198.51.100.144"));
  assert.equal(r.status, 501);
  assert.deepEqual(r.body, { error: "erase_unconfigured" });
  env.ADMIN_TOKEN = "a".repeat(31);
  r = await send(makeEraseRequest(key, "a".repeat(31), "198.51.100.144"));
  assert.equal(r.status, 501);
  assert.deepEqual(r.body, { error: "erase_unconfigured" });
  assert.equal(stub._hasSchema(), true);

  env.ADMIN_TOKEN = token;
  // A wrong token is refused and the record stays
  r = await send(makeEraseRequest(key, token.slice(0, -1) + "X", "198.51.100.145"));
  assert.equal(r.status, 403);
  assert.deepEqual(r.body, { error: "forbidden" });
  assert.equal(stub._hasSchema(), true);

  // Malformed parameters
  r = await send(makeEraseRequest("short", token, "198.51.100.146"));
  assert.equal(r.status, 400);
  assert.deepEqual(r.body, { error: "invalid_params" });

  // The right token wipes the record and nothing else
  r = await send(makeEraseRequest(key, token, "198.51.100.145"));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, erased: true });
  assert.equal(stub._hasSchema(), false);
  assert.equal(otherStub._hasSchema(), true);

  // An unknown key
  r = await send(makeEraseRequest("cs_live_eraseNeverActivated00000000000043", token, "198.51.100.145"));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, erased: false });

  // The sixth request in a minute from one IP address is rate limited
  for (let i = 0; i < 5; i++) {
    r = await send(makeEraseRequest("cs_live_eraseRateLimitProbe000000000000043", token, "198.51.100.147"));
    assert.equal(r.status, 200, `request ${i + 1}`);
  }
  r = await send(makeEraseRequest("cs_live_eraseRateLimitProbe000000000000043", token, "198.51.100.147"));
  assert.equal(r.status, 429);
  assert.deepEqual(r.body, { error: "rate_limited" });
  assert.equal(r.headers.get("Retry-After"), "60");

  // A browser request is refused before anything else
  r = await send(makeEraseRequest(otherKey, token, "198.51.100.148", { Origin: "https://evil.example" }));
  assert.equal(r.status, 403);
  assert.deepEqual(r.body, { error: "forbidden_origin" });
  assert.equal(otherStub._hasSchema(), true);

  for (const b of bodies) assert.equal(b.includes(token), false, "no response echoes the token");

  // A paid key that was erased activates again with a fresh seat count
  const again = await activateAndGetTicket(env, key, "5555666677778888", "198.51.100.149");
  assert.equal(again.seatsUsed, 1);
});

test("43b. seat rows deactivated more than 30 days ago are purged on the next request and by the alarm", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const ip = "198.51.100.150";
  const back31 = 31 * 86_400;

  // Purge on the next request
  const key1 = "cs_live_purgeOnNextRequest00000000000043b";
  const env1 = makePaidEnv(privB64);
  const a1 = await activateAndGetTicket(env1, key1, "1111222233334444", ip);
  await activateAndGetTicket(env1, key1, "5555666677778888", ip);
  assert.equal((await worker.fetch(makeDeactivateRequest(key1, "1111222233334444", a1.ticket, ip), env1)).status, 200);
  const stub1 = env1.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key1)));
  stub1.sql.exec(`UPDATE seats SET deactivated_at = deactivated_at - ? WHERE seat = ?`, back31, "1111222233334444");
  await activateAndGetTicket(env1, key1, "9999aaaabbbbcccc", ip);
  const seats1 = stub1.sql.exec(`SELECT seat FROM seats ORDER BY seat`).toArray().map((r) => r.seat);
  assert.deepEqual(seats1, ["5555666677778888", "9999aaaabbbbcccc"]);

  // Purge by the alarm
  const key2 = "cs_live_purgeByTheAlarm0000000000000043b";
  const env2 = makePaidEnv(privB64);
  const b1 = await activateAndGetTicket(env2, key2, "1111222233334444", ip);
  await activateAndGetTicket(env2, key2, "5555666677778888", ip);
  const stub2 = env2.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key2)));
  assert.equal(await stub2.ctx.storage.getAlarm(), null, "activation alone arms no alarm");
  const before = Date.now();
  assert.equal((await worker.fetch(makeDeactivateRequest(key2, "1111222233334444", b1.ticket, ip), env2)).status, 200);
  const alarmAt = await stub2.ctx.storage.getAlarm();
  const expected = before + (30 * 86_400 + 60) * 1000;
  assert.ok(Math.abs(alarmAt - expected) < 5_000, `alarm about 30 days ahead (got ${alarmAt - before} ms)`);

  stub2.sql.exec(`UPDATE seats SET deactivated_at = deactivated_at - ? WHERE seat = ?`, back31, "1111222233334444");
  await stub2.alarm();
  const rows2 = stub2.sql.exec(`SELECT seat, deactivated_at FROM seats`).toArray();
  assert.equal(rows2.length, 1);
  assert.equal(rows2[0].seat, "5555666677778888");
  assert.equal(rows2[0].deactivated_at, null);
  assert.equal(stub2._hasSchema(), true, "the alarm never wipes a license record");
});

test("43c. /thank-you for a refunded session wipes an existing record", async () => {
  const { privB64 } = await generateEd25519KeyPairB64();
  const key = "cs_live_thankYouRefundWipesRecord00000043c";
  const env = makePaidEnv(privB64);
  await activateAndGetTicket(env, key, "1111222233334444", "198.51.100.151");
  const stub = env.SEAT_DO.get("lic:" + (await sha256HexTest("seatstamp-key-v1|" + key)));
  assert.equal(stub._hasSchema(), true);

  env.__TEST_FETCH = async () =>
    new Response(
      JSON.stringify({
        ...PAID_SESSION_JSON,
        payment_intent: {
          ...PAID_SESSION_JSON.payment_intent,
          latest_charge: { amount: 900, amount_refunded: 900, refunded: true, disputed: false },
        },
      }),
      { status: 200 }
    );
  __resetIsolateStateForTests(env);
  const r = await loadThankYouAndWait(env, key, "198.51.100.152");
  assert.equal(r.status, 403);
  assert.equal(stub._hasSchema(), false);
});

test("44. docs/integrating.md Node verifier matches the golden vectors and rejects revoked tags and loose issued values", async () => {
  const doc = readFileSync(new URL("../docs/integrating.md", import.meta.url), "utf8");
  const blocks = [...doc.matchAll(/```js\n([\s\S]*?)```/g)].map((m) => m[1]);
  const source = blocks.find((b) => b.includes("verifyOfflineTicket"));
  assert.ok(source, "a fenced js block defines verifyOfflineTicket");
  const { verifyOfflineTicket } = await import("data:text/javascript," + encodeURIComponent(source));

  const golden = JSON.parse(readFileSync(new URL("../fixtures/golden-vectors.json", import.meta.url), "utf8"));
  const opts = {
    scheme: golden.ticket.scheme,
    prefix: golden.ticket.prefix,
    publicKeyB64: golden.licenseTestKey.publicKeyBase64,
    expectedSeat: golden.ticket.seat,
  };

  const ok = await verifyOfflineTicket(golden.ticket.encoded, opts);
  assert.ok(ok, "the golden ticket verifies");
  assert.equal(ok.tag, golden.ticket.tag);
  assert.equal(ok.issued, golden.ticket.issued);
  assert.equal(ok.boundSeat, golden.ticket.seat);

  assert.equal(await verifyOfflineTicket(golden.ticket.encoded, { ...opts, revokedOrderTags: ["ord-42a9f01c"] }), null);
  assert.ok(await verifyOfflineTicket(golden.ticket.encoded, { ...opts, revokedOrderTags: ["", "ORD-", "ORD-0011223344556677"] }),
    "empty or unrelated entries never match");

  const signKey = await crypto.subtle.importKey(
    "pkcs8",
    Buffer.from(golden.licenseTestKey.pkcs8Base64, "base64"),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const signTicket = async (payload) => {
    const bytes = new TextEncoder().encode(payload);
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", signKey, bytes));
    return golden.ticket.prefix + Buffer.from(bytes).toString("base64url") + "." + Buffer.from(sig).toString("base64url");
  };
  const loose = await signTicket(`${golden.ticket.scheme}|${golden.ticket.tag}|1.76e9|${golden.ticket.seat}`);
  assert.equal(await verifyOfflineTicket(loose, opts), null, "a scientific-notation issued value is refused");
  const strict = await signTicket(`${golden.ticket.scheme}|${golden.ticket.tag}|1760000000|${golden.ticket.seat}`);
  assert.ok(await verifyOfflineTicket(strict, opts), "the same payload with a plain integer verifies");

  // A universal ticket is checked against revoked tags too
  const universal = await signTicket(`${golden.ticket.scheme}|${golden.ticket.tag}|1760000000`);
  assert.ok(await verifyOfflineTicket(universal, opts));
  assert.equal(await verifyOfflineTicket(universal, { ...opts, revokedOrderTags: ["ORD-42A9F01C"] }), null);
});
