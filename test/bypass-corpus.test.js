import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Hostfence,
  HostfenceError,
  classifyAddress,
  hostnameEmbeddedIPs,
} from "../dist/index.js";

const noDns = async () => {
  throw new Error("Unexpected DNS lookup");
};

const fence = new Hostfence({ lookup: noDns });

describe("hostname-embedded IPs", () => {
  it("reads dotted and dashed wildcard DNS products", () => {
    assert.deepEqual(hostnameEmbeddedIPs("127.0.0.1.nip.io"), ["127.0.0.1"]);
    assert.deepEqual(hostnameEmbeddedIPs("10-0-0-1.sslip.io"), ["10.0.0.1"]);
    assert.deepEqual(hostnameEmbeddedIPs("app.127.0.0.1.xip.io"), ["127.0.0.1"]);
  });

  it("treats convenience loopback zones as 127.0.0.1", () => {
    assert.deepEqual(hostnameEmbeddedIPs("localtest.me"), ["127.0.0.1"]);
    assert.deepEqual(hostnameEmbeddedIPs("foo.lvh.me"), ["127.0.0.1"]);
    assert.deepEqual(hostnameEmbeddedIPs("vcap.me"), ["127.0.0.1"]);
  });
});

describe("transition-prefix unwrapping", () => {
  it("classifies NAT64 and 6to4 by the embedded IPv4", () => {
    assert.equal(classifyAddress("64:ff9b::7f00:1"), "loopback");
    assert.equal(classifyAddress("64:ff9b::a00:1"), "private");
    assert.equal(classifyAddress("2002:7f00:1::"), "loopback");
    assert.equal(classifyAddress("2002:0a00:0001::"), "private");
    assert.equal(classifyAddress("64:ff9b::0808:0808"), "public");
  });

  it("keeps Azure wire-server and AWS IPv6 IMDS as metadata", () => {
    assert.equal(classifyAddress("168.63.129.16"), "metadata");
    assert.equal(classifyAddress("fd00:ec2::254"), "metadata");
  });

  it("treats Teredo 2001::/32 as reserved", () => {
    assert.equal(classifyAddress("2001::1"), "reserved");
  });
});

describe("SSRF bypass corpus", () => {
  const blocked = [
    "http://127.1/",
    "http://127.0.1/",
    "http://0x7f.1/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[64:ff9b::7f00:1]/",
    "http://[2002:7f00:1::]/",
    "http://127.0.0.1.nip.io/",
    "http://127-0-0-1.sslip.io/latest",
    "http://localtest.me/",
    "http://foo.lvh.me/",
    "http://metadata/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/latest/meta-data",
    "http://168.63.129.16/",
    "http://[fd00:ec2::254]/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "file:///etc/passwd",
    "gopher://127.0.0.1/",
    "http://localhost/",
    "https://user:pass@1.1.1.1/",
  ];

  for (const url of blocked) {
    it(`blocks ${url}`, async () => {
      const result = await fence.check(url);
      assert.equal(result.ok, false, result.reasons.join("; "));
      assert.equal(result.pin, null);
    });
  }

  it("pins a public literal", async () => {
    const result = await fence.check("https://1.1.1.1/dns-query");
    assert.equal(result.ok, true);
    assert.deepEqual(result.pin, {
      address: "1.1.1.1",
      family: 4,
      port: 443,
      servername: "1.1.1.1",
    });
  });

  it("pins the first allowed DNS answer", async () => {
    const local = new Hostfence({ lookup: async () => ["8.8.8.8", "1.1.1.1"] });
    const { url, pin } = await local.assertPin("https://dns.example/query");
    assert.equal(url.hostname, "dns.example");
    assert.equal(pin.address, "8.8.8.8");
    assert.equal(pin.family, 4);
    assert.equal(pin.port, 443);
    assert.equal(pin.servername, "dns.example");
  });

  it("refuses to pin when any DNS answer is internal", async () => {
    const local = new Hostfence({ lookup: async () => ["1.1.1.1", "10.0.0.5"] });
    await assert.rejects(() => local.assertPin("https://rebinder.example/"), HostfenceError);
  });

  it("checks redirect hops against the same policy", async () => {
    const result = await fence.checkHop("https://1.1.1.1/start", "http://169.254.169.254/");
    assert.equal(result.ok, false);
  });

  it("resolves relative redirect hops", async () => {
    const local = new Hostfence({ lookup: async () => ["1.1.1.1"] });
    const result = await local.checkHop("https://partner.example/a", "/b");
    assert.equal(result.ok, true);
    assert.equal(result.url.hostname, "partner.example");
    assert.equal(result.url.pathname, "/b");
  });
});
