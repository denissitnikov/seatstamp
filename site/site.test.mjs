// Keeps the walkthrough site honest: its examples must match the real formats, flags, secrets, and API.
// Run: node --test site/site.test.mjs (Node 22.12+, no npm install)

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const html = read("./index.html");
const appJS = read("./app.js");
const golden = JSON.parse(read("../fixtures/golden-vectors.json"));
const licenseTool = read("../Sources/license-tool/main.swift");
const manager = read("../Sources/SeatStamp/SeatStampManager.swift");
const worker = read("../worker/worker.js");

const vectors = (() => {
  const match = appJS.match(/var VECTORS = (\{[\s\S]*?\n {2}\});/);
  assert.ok(match, "app.js defines VECTORS");
  return JSON.parse(JSON.stringify(vm.runInNewContext(`(${match[1]})`)));
})();

const b64 = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

async function verify(publicKeyB64, signature, message) {
  const key = await webcrypto.subtle.importKey("raw", b64(publicKeyB64), { name: "Ed25519" }, false, ["verify"]);
  return webcrypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
}

test("site vectors are copied exactly from fixtures/golden-vectors.json", () => {
  assert.equal(vectors.licensePublicKeyBase64, golden.licenseTestKey.publicKeyBase64);
  assert.equal(vectors.updatePublicKeyBase64, golden.updateTestKey.publicKeyBase64);
  assert.equal(vectors.ticket.encoded, golden.ticket.encoded);
  assert.equal(vectors.ticket.seat, golden.ticket.seat);
  const m = golden.manifestWithSequence;
  assert.deepEqual(
    vectors.manifest,
    {
      version: m.version,
      url: m.url,
      summary: m.summary,
      notes: m.notes,
      revokedTags: m.revokedTags,
      sha256: m.sha256,
      size: m.size,
      manifestSeq: m.manifestSeq,
      canonicalUTF8: m.canonicalUTF8,
      signatureBase64URL: m.signatureBase64URL,
    },
  );
});

test("the ticket shown on the site verifies, and the site's tampered ticket does not", async () => {
  const [payload, sig] = vectors.ticket.encoded.slice(4).split(".");
  assert.ok(await verify(vectors.licensePublicKeyBase64, b64(sig), b64(payload)));
  const fields = b64(payload).toString("utf8").split("|");
  assert.deepEqual(fields, golden.ticket.canonicalPayload.split("|"));
  fields[3] = "5f0c9a17e2b4d863";
  assert.equal(await verify(vectors.licensePublicKeyBase64, b64(sig), Buffer.from(fields.join("|"))), false);
});

test("the manifest shown on the site verifies, and a changed URL does not", async () => {
  const m = vectors.manifest;
  const sig = b64(m.signatureBase64URL);
  assert.ok(await verify(vectors.updatePublicKeyBase64, sig, Buffer.from(m.canonicalUTF8)));
  const evil = "https://evil.example/download/Acme-2.0.1.dmg";
  const edited = m.canonicalUTF8.replace(`${m.url.length}:${m.url}`, `${evil.length}:${evil}`);
  assert.notEqual(edited, m.canonicalUTF8);
  assert.equal(await verify(vectors.updatePublicKeyBase64, sig, Buffer.from(edited)), false);
});

test("no retired names or invented identifiers on the site", () => {
  const retired = [
    "LicenseKit", "licensekit", "indie-license-kit", "minIssued", "seatID", "version2.json",
    "ED25519_PRIVATE_KEY_HEX", "--keygen", "manifestPrivateKey", "revoked_keys", "download_url", "\u2014", "\u2013",
  ];
  for (const [name, text] of [["index.html", html], ["app.js", appJS]]) {
    for (const word of retired) assert.ok(!text.includes(word), `${name} contains "${word}"`);
  }
});

test("every license-tool flag on the site exists", () => {
  const flags = new Set([...(html + appJS).matchAll(/license-tool[^<\n]*/g)].flatMap((m) => m[0].match(/--[a-z-]+/g) || []));
  assert.ok(flags.size >= 4, `found flags: ${[...flags]}`);
  for (const flag of flags) assert.ok(licenseTool.includes(`"${flag}"`), `license-tool has no ${flag}`);
});

test("every Worker secret and var on the site exists in worker.js", () => {
  const names = new Set([...(html + appJS).matchAll(/\b(?:ED25519|STRIPE|RESEND|ADMIN|SEAT|TICKET|APP)_[A-Z0-9_]+/g)].map((m) => m[0]));
  assert.ok(names.has("ED25519_PKCS8_B64"));
  for (const name of names) assert.ok(worker.includes(name), `worker.js never mentions ${name}`);
});

test("the Swift sample uses the real initializer labels and ActivationOutcome cases", () => {
  const sample = html.match(/<pre id="code-step-4"><code>([\s\S]*?)<\/code><\/pre>/)[1];
  const labels = [...sample.matchAll(/^\s{4}(\w+):/gm)].map((m) => m[1]);
  assert.ok(labels.length >= 6);
  for (const label of labels) assert.match(manager, new RegExp(`\\b${label}:`), `SeatStampManager.init has no ${label}:`);
  const enumBody = manager.match(/public enum ActivationOutcome[^{]*\{([\s\S]*?)\n {4}\}/)[1];
  const realCases = [...enumBody.matchAll(/case (\w+)/g)].map((m) => m[1]).sort();
  const siteCases = [...sample.matchAll(/case \.(\w+)/g)].map((m) => m[1]).sort();
  assert.deepEqual(siteCases, realCases, "the switch covers exactly the real cases");
  assert.match(sample, /kit\.activate\(key:/);
});
