import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Hostfence, HostfenceError, canonicalizeHost, classifyAddress } from "../dist/index.js";

const noDns = async () => { throw new Error("Unexpected DNS lookup"); };

// These are regression fixtures, not live DNS requests or network probes.
describe("address classification regressions", () => {
  const fixtures = [
    ["1.1.1.1", "public"], ["2606:4700:4700::1111", "public"],
    ["0.0.0.0", "unspecified"], ["0.255.255.255", "unspecified"],
    ["127.255.255.255", "loopback"], ["::0001", "loopback"],
    ["0000:0000:0000:0000:0000:0000:0000:0001", "loopback"],
    ["0::0", "unspecified"], ["169.254.255.255", "link-local"],
    ["febf:ffff::1", "link-local"], ["fc00::1", "unique-local"],
    ["fdff:ffff::1", "unique-local"], ["100.64.0.0", "cgnat"],
    ["100.127.255.255", "cgnat"], ["100.128.0.0", "public"],
    ["100.100.100.200", "metadata"], ["10.255.255.255", "private"],
    ["172.31.255.255", "private"], ["172.32.0.0", "public"],
    ["192.168.255.255", "private"], ["224.0.0.0", "multicast"],
    ["239.255.255.255", "multicast"], ["255.255.255.255", "multicast"],
    ["ff02::1", "multicast"], ["240.0.0.1", "reserved"],
    ["255.255.255.254", "reserved"], ["192.0.0.1", "reserved"],
    ["100::1", "reserved"], ["64:ff9b:1::a00:1", "reserved"],
    ["100:0:0:1::1", "reserved"], ["5f00::1", "reserved"],
    ["192.0.2.1", "documentation"], ["198.51.100.1", "documentation"],
    ["203.0.113.1", "documentation"], ["198.19.255.255", "documentation"],
    ["2001:db8::1", "documentation"], ["2001:2::1", "documentation"],
    ["3fff:fff::1", "documentation"], ["3fff:1000::1", "public"],
    ["::ffff:127.0.0.1", "loopback"],
    ["0:0:0:0:0:ffff:127.0.0.1", "loopback"],
    ["0000:0:0:0:0:ffff:10.20.30.40", "private"],
    ["0:0:0:0:0:ffff:7f00:1", "loopback"],
    ["::ffff:f000:1", "reserved"], ["::ffff:1.1.1.1", "public"],
    ["not-an-ip", "invalid"], ["", "invalid"],
    ["127.0.0.1.example", "invalid"], ["::ffff:999.0.0.1", "invalid"],
    ["2001:4860::8888%en0", "invalid"], ["[::1]", "invalid"],
  ];
  for (const [address, expected] of fixtures) {
    it(`${address || "empty string"} is ${expected}`, () => {
      assert.equal(classifyAddress(address), expected);
    });
  }
});

describe("fail-closed DNS", () => {
  for (const records of [undefined, null, "1.1.1.1", {}, [undefined], new Array(1), ["not-an-ip"], ["1.1.1.1", "invalid"], ["::ffff:999.0.0.1"], ["2606:4700::1111%en0"]]) {
    it(`blocks malformed resolver output: ${JSON.stringify(records)}`, async () => {
      const fence = new Hostfence({ lookup: async () => records });
      const result = await fence.check("https://test.example/");
      assert.equal(result.ok, false);
      assert.match(result.reasons.join(";"), /invalid/);
    });
  }
  it("rejects an empty result", async () => {
    const result = await new Hostfence({ lookup: async () => [] }).check("https://test.example/");
    assert.deepEqual(result.reasons, ["hostname resolved to no addresses"]);
  });
  it("bounds a stalled resolver", { timeout: 1000 }, async () => {
    const fence = new Hostfence({ lookup: () => new Promise(() => {}), lookupTimeoutMs: 10 });
    const result = await fence.check("https://test.example/");
    assert.equal(result.ok, false);
    assert.match(result.reasons[0], /timed out after 10ms/);
  });
  it("turns resolver exceptions into structured reasons", async () => {
    const result = await new Hostfence({ lookup: () => { throw new Error("offline"); } }).check("https://test.example/");
    assert.deepEqual(result.reasons, ["DNS lookup failed: offline"]);
  });
  it("checks every answer and deduplicates repeated records", async () => {
    const result = await new Hostfence({ lookup: async () => ["1.1.1.1", "1.1.1.1", "0:0:0:0:0:ffff:127.0.0.1"] }).check("https://test.example/");
    assert.equal(result.ok, false);
    assert.equal(result.addresses.length, 2);
    assert.match(result.reasons[0], /loopback/);
  });
  it("does not resolve a hostname rejected by its allow list", async () => {
    let calls = 0;
    const fence = new Hostfence({ allowedHosts: ["api.example"], lookup: async () => { calls++; return ["1.1.1.1"]; } });
    const result = await fence.check("https://other.example/");
    assert.equal(result.ok, false);
    assert.equal(calls, 0);
  });
  it("still validates DNS for an allowed hostname", async () => {
    const fence = new Hostfence({ allowedHosts: ["api.example"], lookup: async () => ["10.0.0.1"] });
    await assert.rejects(() => fence.assert("https://api.example/"), HostfenceError);
  });
});

describe("destination policy", () => {
  it("rejects credentials before DNS", async () => {
    const result = await new Hostfence({ lookup: noDns }).check("https://user:secret@api.example/");
    assert.deepEqual(result.reasons, ["URL credentials are not allowed"]);
  });
  it("supports explicit credential opt-in", async () => {
    const result = await new Hostfence({ allowCredentials: true, lookup: noDns }).check("https://user:secret@1.1.1.1/");
    assert.equal(result.ok, true);
  });
  it("checks implicit and explicit destination ports", async () => {
    const fence = new Hostfence({ allowedPorts: [443], lookup: noDns });
    assert.equal((await fence.check("https://1.1.1.1/")).ok, true);
    assert.equal((await fence.check("https://1.1.1.1:443/")).ok, true);
    assert.equal((await fence.check("http://1.1.1.1/")).ok, false);
    assert.equal((await fence.check("https://1.1.1.1:8443/")).ok, false);
  });
  it("treats an empty port policy as deny all", async () => {
    assert.equal((await new Hostfence({ allowedPorts: [] }).check("https://1.1.1.1/")).ok, false);
  });
  it("normalizes Unicode, case, and trailing dots consistently", async () => {
    const names = [];
    const fence = new Hostfence({ allowedHosts: [" BÜCHER.Example. "], lookup: async (hostname) => { names.push(hostname); return ["1.1.1.1"]; } });
    const url = await fence.assert("https://xn--bcher-kva.example./path");
    assert.equal(url.hostname, "xn--bcher-kva.example");
    assert.deepEqual(names, ["xn--bcher-kva.example"]);
  });
  it("normalizes denied hostnames the same way", async () => {
    const result = await new Hostfence({ extraDeniedHosts: [" BÜCHER.Example. "], lookup: noDns }).check("https://xn--bcher-kva.example/");
    assert.deepEqual(result.reasons, ["hostname is on the deny list"]);
  });
  it("normalizes numeric and bracketed IP policy entries", async () => {
    const fence = new Hostfence({ allowedHosts: ["0x01010101", "[2606:4700:4700:0:0:0:0:1111]"], lookup: noDns });
    assert.equal((await fence.check("https://1.1.1.1/")).ok, true);
    assert.equal((await fence.check("https://[2606:4700:4700::1111]/")).ok, true);
  });
  it("a deny rule wins over an allow rule", async () => {
    const result = await new Hostfence({ allowedHosts: ["api.example"], extraDeniedHosts: ["API.EXAMPLE."], lookup: noDns }).check("https://api.example/");
    assert.equal(result.ok, false);
    assert.deepEqual(result.reasons, ["hostname is on the deny list"]);
  });
  it("blocks equivalent IPv4-mapped addresses through CIDR rules", async () => {
    const result = await new Hostfence({ extraDeniedCidrs: ["1.1.1.0/24"], lookup: noDns }).check("https://[::ffff:1.1.1.1]/");
    assert.equal(result.ok, false);
    assert.match(result.reasons[0], /extra denied CIDR/);
  });
  it("blocks mapped IPv6 CIDRs for a plain IPv4 destination", async () => {
    const result = await new Hostfence({ extraDeniedCidrs: ["::ffff:101:100/120"], lookup: noDns }).check("https://1.1.1.1/");
    assert.equal(result.ok, false);
  });
  it("supports IPv6 CIDR policies", async () => {
    const result = await new Hostfence({ extraDeniedCidrs: ["2606:4700::/32"], lookup: noDns }).check("https://[2606:4700:4700::1111]/");
    assert.equal(result.ok, false);
  });
  it("does not let allowLoopback enable unspecified addresses", async () => {
    const fence = new Hostfence({ allowLoopback: true, lookup: noDns });
    assert.equal((await fence.check("http://127.0.0.1/")).ok, true);
    assert.equal((await fence.check("http://0.0.0.0/")).ok, false);
  });
  it("retains invalid URL error codes", async () => {
    await assert.rejects(() => new Hostfence().check("not a URL"), { code: "HOSTFENCE_INVALID_URL" });
  });
});

describe("configuration validation", () => {
  for (const cidr of ["1.1.1.1", "10.0.0.0/", "10.0.0.0/8/24", "10.0.0.0/8.5", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/0x8", "10.0.0.0/ 8", "::/129", "fe80::%en0/64", "invalid/24"]) {
    it(`rejects invalid CIDR ${cidr}`, () => {
      assert.throws(() => new Hostfence({ extraDeniedCidrs: [cidr] }), TypeError);
    });
  }
  for (const lookupTimeoutMs of [0, -1, 0.5, Infinity, NaN, 2147483648]) {
    it(`rejects invalid timeout ${lookupTimeoutMs}`, () => {
      assert.throws(() => new Hostfence({ lookupTimeoutMs }), TypeError);
    });
  }
  for (const port of [0, -1, 65536, 1.5, NaN, "443"]) {
    it(`rejects invalid port ${port}`, () => {
      assert.throws(() => new Hostfence({ allowedPorts: [port] }), TypeError);
    });
  }
  for (const host of ["https://example.com", "example.com:443", "*.example.com", "user@example.com", "", "[fe80::1%en0]"]) {
    it(`rejects non-host policy entry ${host}`, () => {
      assert.throws(() => new Hostfence({ allowedHosts: [host] }), TypeError);
    });
  }
});

describe("URL parser compatibility", () => {
  for (const host of ["017700000001", "0x7f000001", "2130706433", "127.1", "0177.0.0.1", "127.0.0.1."]) {
    it(`normalizes and blocks ${host}`, async () => {
      assert.equal(canonicalizeHost(host), "127.0.0.1");
      const result = await new Hostfence({ lookup: noDns }).check(`http://${host}/`);
      assert.equal(result.ok, false);
      assert.equal(result.hostname, "127.0.0.1");
    });
  }
});
