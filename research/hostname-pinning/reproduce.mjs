import assert from "node:assert/strict";
import { readFileSync, realpathSync, lstatSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { Hostfence as Before } from "hostfence-before";
import { Hostfence as After } from "hostfence-after";

const revisions = {
  before: {
    name: "hostfence-before", version: "1.4.0",
    commit: "4df230828e7a8b3055c9ffba8ff2b982be313a03", Constructor: Before,
  },
  after: {
    name: "hostfence-after", version: "1.4.1",
    commit: "3d450931930a5a69f97b6ef27eb9b3f527b3d862", Constructor: After,
  },
};

const root = new URL("./", import.meta.url);
const lock = JSON.parse(readFileSync(new URL("package-lock.json", root), "utf8"));
const dependencies = {};
for (const [label, revision] of Object.entries(revisions)) {
  const directory = new URL(`node_modules/${revision.name}/`, root);
  const manifest = JSON.parse(readFileSync(new URL("package.json", directory), "utf8"));
  const entry = lock.packages[`node_modules/${revision.name}`];
  assert.ok(entry, `${label}: dependency must be present in this fixture's lockfile`);
  assert.equal(entry.link, undefined, `${label}: workspace links are not accepted`);
  assert.equal(lstatSync(directory).isSymbolicLink(), false, `${label}: no package symlink`);
  assert.equal(realpathSync(directory), resolve(fileURLToPath(directory)), `${label}: no ancestor symlink`);
  assert.equal(manifest.name, "hostfence");
  assert.equal(manifest.version, revision.version);
  assert.equal(entry.resolved, `git+ssh://git@github.com/hon900/hostfence.git#${revision.commit}`);
  dependencies[label] = {
    package: manifest.name, version: manifest.version, commit: revision.commit,
    resolved: entry.resolved, workspaceLink: false,
  };
}

// All resolution is supplied below. No HTTP client or system DNS lookup is used.
const cases = [
  {
    id: "hint-differs-from-dns", url: "https://8.8.8.8.nip.io/",
    records: ["1.1.1.1"], calls: 1,
    expected: { before: [true, "8.8.8.8"], after: [true, "1.1.1.1"] },
  },
  {
    id: "empty-dns-with-public-hint", url: "https://8-8-8-8.sslip.io/",
    records: [], calls: 1,
    expected: { before: [true, "8.8.8.8"], after: [false, null] },
  },
  {
    id: "private-dns-answer", url: "https://8.8.8.8.nip.io/",
    records: ["127.0.0.1"], calls: 1,
    expected: { before: [false, null], after: [false, null] },
  },
  {
    id: "mixed-public-private-dns", url: "https://8.8.8.8.nip.io/",
    records: ["1.1.1.1", "10.0.0.5"], calls: 1,
    expected: { before: [false, null], after: [false, null] },
  },
  {
    id: "private-hostname-hint", url: "https://127.0.0.1.nip.io/",
    records: ["1.1.1.1"], calls: 0,
    expected: { before: [false, null], after: [false, null] },
  },
  {
    id: "ordinary-public-dns", url: "https://ordinary.invalid/",
    records: ["1.1.1.1"], calls: 1,
    expected: { before: [true, "1.1.1.1"], after: [true, "1.1.1.1"] },
  },
];

const results = [];
for (const fixture of cases) {
  const result = { id: fixture.id, url: fixture.url, injectedDnsAnswers: fixture.records };
  for (const [label, { Constructor }] of Object.entries(revisions)) {
    let lookupCalls = 0;
    const fence = new Constructor({
      lookup: async (hostname) => {
        assert.equal(hostname, new URL(fixture.url).hostname);
        lookupCalls++;
        return [...fixture.records];
      },
    });
    const checked = await fence.check(fixture.url);
    const [allowed, pinAddress] = fixture.expected[label];
    assert.equal(checked.ok, allowed, `${fixture.id}/${label}: policy result`);
    assert.equal(checked.pin?.address ?? null, pinAddress, `${fixture.id}/${label}: destination pin`);
    assert.equal(lookupCalls, fixture.calls, `${fixture.id}/${label}: resolver calls`);
    if (allowed) {
      assert.equal(checked.reasons.length, 0);
      assert.equal(checked.pin.servername, new URL(fixture.url).hostname);
      assert.equal(checked.pin.port, 443);
    } else {
      assert.ok(checked.reasons.length > 0, `${fixture.id}/${label}: rejection reason`);
    }
    if (label === "after" && checked.pin) {
      assert.ok(fixture.records.includes(checked.pin.address), "the fixed pin must be an actual DNS answer");
    }
    if (label === "after" && fixture.id === "empty-dns-with-public-hint") {
      assert.deepEqual(checked.reasons, ["hostname resolved to no addresses"]);
    }
    result[label] = {
      ok: checked.ok, addresses: checked.addresses, pin: checked.pin,
      reasons: checked.reasons, lookupCalls,
      pinMatchesInjectedDns: checked.pin ? fixture.records.includes(checked.pin.address) : null,
    };
  }
  results.push(result);
}

console.log(JSON.stringify({
  schemaVersion: 1,
  study: "hostname-evidence-vs-dns-pinning",
  generatedAt: new Date().toISOString(),
  runtime: { node: process.version, platform: process.platform, architecture: process.arch },
  method: "Injected resolver fixtures only; no HTTP requests or public DNS queries during this program.",
  dependencies,
  result: "PASS",
  caseCount: results.length,
  results,
}, null, 2));
