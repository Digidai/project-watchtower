import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(new URL("../cloudflare/oracle-watchtower-proxy.js", import.meta.url));
const { default: worker } = await import(`data:text/javascript;base64,${source.toString("base64")}`);
const env = { WATCHTOWER_ORIGIN_SECRET: "test-origin-secret" };

test("HTTP redirects and missing credentials fail closed", async () => {
  assert.equal((await worker.fetch(new Request("http://oracle.syncany.app/"), env)).status, 308);
  assert.equal((await worker.fetch(new Request("https://oracle.syncany.app/"), {})).status, 503);
});

test("worker authenticates HTTPS origin and preserves a bounded login body", async (t) => {
  t.mock.method(globalThis, "fetch", async (target, init) => {
    assert.equal(target.origin, "https://oracle-origin.syncany.app");
    assert.equal(init.headers.get("X-Watchtower-Origin"), env.WATCHTOWER_ORIGIN_SECRET);
    assert.equal(init.headers.get("X-Watchtower-Client-IP"), "1.1.1.1");
    assert.equal(init.headers.get("X-Forwarded-Proto"), "https");
    assert.equal(init.headers.get("Origin"), "https://oracle.syncany.app");
    assert.equal(new TextDecoder().decode(init.body), "password=test");
    assert.equal(init.headers.get("Content-Length"), "13");
    return new Response(null, { status: 303, headers: { "X-Watchtower-App": "dashboard-v2", Location: "/", "Set-Cookie": "test=redacted; Secure" } });
  });
  const request = new Request("https://oracle.syncany.app/login", { method: "POST", body: "password=test",
    headers: { "Origin": "https://oracle.syncany.app:443/login", "Sec-Fetch-Site": "same-origin",
      "X-Watchtower-Origin": "spoofed", "X-Watchtower-Client-IP": "8.8.8.8", "CF-Connecting-IP": "1.1.1.1" } });
  const response = await worker.fetch(request, env);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("Cache-Control"), "no-store, max-age=0");
  assert.match(response.headers.get("Set-Cookie"), /Secure/);
});

test("privacy-preserving same-origin login works and cross-site login is rejected", async (t) => {
  let fetches = 0;
  t.mock.method(globalThis, "fetch", async (_target, init) => {
    fetches += 1;
    assert.equal(init.headers.get("Origin"), "https://oracle.syncany.app");
    return new Response(null, { status: 303, headers: { "X-Watchtower-App": "dashboard-v2", Location: "/" } });
  });
  const privacyRequest = new Request("https://oracle.syncany.app/login", { method: "POST", body: "password=test",
    headers: { "Origin": "null", "Sec-Fetch-Site": "same-origin" } });
  assert.equal((await worker.fetch(privacyRequest, env)).status, 303);
  assert.equal((await worker.fetch(new Request("https://oracle.syncany.app/login", { method: "POST", body: "password=test",
    headers: { "Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site" } }), env)).status, 403);
  assert.equal((await worker.fetch(new Request("https://oracle.syncany.app/login", { method: "POST", body: "password=test" }), env)).status, 403);
  assert.equal(fetches, 1);
});

test("wrong origin response and oversized body never expose a login", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response("unrelated-server", { status: 404 }));
  const response = await worker.fetch(new Request("https://oracle.syncany.app/"), env);
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /<form/);
  assert.equal((await worker.fetch(new Request("https://oracle.syncany.app/login", { method: "POST", body: "x".repeat(4097),
    headers: { "Origin": "https://oracle.syncany.app" } }), env)).status, 413);
});
