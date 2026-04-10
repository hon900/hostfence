import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hostfence, HostfenceError, canonicalizeHost } from "../dist/index.js";

const fence = new Hostfence({
  lookup: async () => {
    throw new Error("unexpected DNS");
  },
});

describe("canonicalizeHost", () => {
  it("expands decimal IPv4 dwords", () => {
    assert.equal(canonicalizeHost("2130706433"), "127.0.0.1");
  });

  it("expands hex IPv4 dwords", () => {
    assert.equal(canonicalizeHost("0x7f000001"), "127.0.0.1");
  });
});

describe("Hostfence.assert", () => {
  it("blocks loopback IPv4", async () => {
    await assert.rejects(() => fence.assert("http://127.0.0.1/latest"), HostfenceError);
  });

  it("blocks decimal loopback", async () => {
    await assert.rejects(() => fence.assert("http://2130706433/"), HostfenceError);
  });

  it("blocks RFC1918", async () => {
    await assert.rejects(() => fence.assert("http://10.1.2.3/admin"), HostfenceError);
    await assert.rejects(() => fence.assert("http://192.168.0.20/"), HostfenceError);
    await assert.rejects(() => fence.assert("http://172.16.9.9/"), HostfenceError);
  });

  it("blocks cloud metadata", async () => {
    await assert.rejects(() => fence.assert("http://169.254.169.254/latest/meta-data"), HostfenceError);
    await assert.rejects(() => fence.assert("http://metadata.google.internal/"), HostfenceError);
  });

  it("blocks localhost names without DNS", async () => {
    await assert.rejects(() => fence.assert("http://localhost:8080/"), HostfenceError);
  });

  it("blocks IPv4-mapped IPv6 loopback", async () => {
    await assert.rejects(() => fence.assert("http://[::ffff:127.0.0.1]/"), HostfenceError);
  });

  it("blocks IPv6 loopback", async () => {
    await assert.rejects(() => fence.assert("http://[::1]/"), HostfenceError);
  });

  it("blocks non-http protocols", async () => {
    await assert.rejects(() => fence.assert("file:///etc/passwd"), HostfenceError);
    await assert.rejects(() => fence.assert("gopher://example.com/"), HostfenceError);
  });

  it("allows a public IP", async () => {
    const url = await fence.assert("https://1.1.1.1/dns-query");
    assert.equal(url.hostname, "1.1.1.1");
  });

  it("blocks DNS records that resolve to private addresses", async () => {
    const local = new Hostfence({
      lookup: async () => ["127.0.0.1", "1.1.1.1"],
    });
    await assert.rejects(() => local.assert("https://rebinder.example/"), HostfenceError);
  });

  it("allows DNS records that are all public", async () => {
    const publicFence = new Hostfence({
      lookup: async () => ["1.1.1.1", "8.8.8.8"],
    });
    const url = await publicFence.assert("https://dns.example/");
    assert.equal(url.hostname, "dns.example");
  });

  it("honors an allow list", async () => {
    const allowed = new Hostfence({
      allowedHosts: ["api.partner.test"],
      lookup: async () => ["1.1.1.1"],
    });
    await assert.rejects(() => allowed.assert("https://evil.example/"), HostfenceError);
    const url = await allowed.assert("https://api.partner.test/v1");
    assert.equal(url.hostname, "api.partner.test");
  });

  it("returns structured check results", async () => {
    const result = await fence.check("http://192.168.1.1/router");
    assert.equal(result.ok, false);
    assert.ok(result.reasons.length > 0);
  });
});
