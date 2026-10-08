import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { lstat, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { Agent } from "undici";
import * as controlledCore from "hostfence";
import * as before from "undici-ssrf-before";
import * as after from "undici-ssrf-after";

const PUBLIC_ANSWER = "93.184.216.34"; // Policy input only; never an HTTP target.
const LOOPBACK = "127.0.0.1";
const HOSTNAME = "connector-case.invalid";
const commits = {
  before: "babdbe5e3f8071eab991014969f0c1c572d47d7c",
  after: "7909f718c9302c053508a1a51cce2c339aa0e7b0",
  controlledCore: "3d450931930a5a69f97b6ef27eb9b3f527b3d862",
};

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const lockBytes = await readFile(new URL("./package-lock.json", import.meta.url));
const lock = JSON.parse(lockBytes);
assert.equal(lock.packages["node_modules/undici"].version, "6.29.0");
for (const [alias, commit] of [["before", commits.before], ["after", commits.after]]) {
  assert.ok(lock.packages[`node_modules/undici-ssrf-${alias}`].resolved.endsWith(`#${commit}`));
}
const coreLocks = Object.values(lock.packages).filter((entry) =>
  entry.resolved?.includes("hon900/hostfence.git#"));
assert.equal(coreLocks.length, 1, "the experiment must not silently install different nested core versions");
assert.equal(coreLocks[0].version, "1.4.1");
assert.ok(coreLocks[0].resolved.endsWith(`#${commits.controlledCore}`));
assert.equal(before.HostfenceError, controlledCore.HostfenceError, "historical adapter must import the controlled core instance");
assert.equal(after.HostfenceError, controlledCore.HostfenceError, "fixed adapter must import the same controlled core instance");
const installedCore = JSON.parse(await readFile(new URL("./node_modules/hostfence/package.json", import.meta.url)));
assert.equal(installedCore.version, "1.4.1");
for (const name of ["hostfence", "undici", "undici-ssrf-before", "undici-ssrf-after"]) {
  assert.equal((await lstat(new URL(`./node_modules/${name}`, import.meta.url))).isSymbolicLink(), false,
    "research dependencies must be standalone installs, not workspace links");
}
const installedTransport = JSON.parse(await readFile(new URL("./node_modules/undici/package.json", import.meta.url)));
assert.equal(installedTransport.version, "6.29.0");
const installedAdapters = {};
for (const [alias, version] of [["before", "0.9.0"], ["after", "0.9.1"]]) {
  const base = new URL(`./node_modules/undici-ssrf-${alias}/`, import.meta.url);
  const manifest = JSON.parse(await readFile(new URL("package.json", base)));
  assert.equal(manifest.version, version);
  assert.equal(manifest.exports, "./src/index.js");
  installedAdapters[alias] = {
    packageVersionField: manifest.version,
    path: `node_modules/undici-ssrf-${alias}`,
    sourceSha256: digest(await readFile(new URL("src/index.js", base))),
    isWorkspaceLink: false,
  };
}

async function withLocalServer(run) {
  const observation = { sockets: 0, requests: 0, hostMatches: true, peersAreLoopback: true };
  const server = createServer((request, response) => {
    observation.requests++;
    observation.hostMatches &&= request.headers.host === `${HOSTNAME}:${server.address().port}`;
    response.end("loopback fixture");
  });
  server.on("connection", (socket) => {
    observation.sockets++;
    observation.peersAreLoopback &&= socket.remoteAddress === LOOPBACK && socket.localAddress === LOOPBACK;
  });
  server.listen(0, LOOPBACK);
  await once(server, "listening");
  try {
    return await run(`http://${HOSTNAME}:${server.address().port}`, observation);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

const results = [];

results.push(await withLocalServer(async (origin, server) => {
  let policyLookups = 0;
  let constructorLookups = 0;
  let requestLookupCalls = 0;
  let assignedPin;
  const agent = new Agent({
    connections: 1,
    connect: {
      timeout: 1000,
      lookup(hostname, options, callback) {
        // Controlled stand-in for the second transport resolver, not public DNS.
        assert.equal(hostname, HOSTNAME);
        constructorLookups++;
        if (options?.all) callback(null, [{ address: LOOPBACK, family: 4 }]);
        else callback(null, LOOPBACK, 4);
      },
    },
  });
  const observeRequestPin = (dispatch) => function observed(options, handler) {
    assert.equal(typeof options.connect?.lookup, "function");
    // Probe the assigned function without opening a socket, separately from its
    // actual transport call count. If transport ever invokes our wrapper, fail
    // closed instead of allowing the public policy address onto the network.
    options.connect.lookup(HOSTNAME, {}, (error, address, family) => {
      assert.ifError(error);
      assignedPin = { address, family };
    });
    options.connect.lookup = (...args) => {
      requestLookupCalls++;
      args.at(-1)(new Error("request-level lookup unexpectedly used; external targets disabled"));
    };
    return dispatch(options, handler);
  };
  const dispatcher = agent.compose(observeRequestPin, before.createSsrfInterceptor({
    lookup: async (hostname) => {
      assert.equal(hostname, HOSTNAME);
      policyLookups++;
      return [PUBLIC_ANSWER];
    },
    // No allowLoopback exception: strict default address restrictions apply.
  }));
  try {
    const response = await dispatcher.request({ origin, path: "/", method: "GET" });
    assert.equal(await response.body.text(), "loopback fixture");
    assert.deepEqual(assignedPin, { address: PUBLIC_ANSWER, family: 4 });
    assert.equal(policyLookups, 1);
    assert.equal(constructorLookups, 1);
    assert.equal(requestLookupCalls, 0);
    assert.equal(server.sockets, 1);
    assert.equal(server.requests, 1);
    assert.ok(server.hostMatches && server.peersAreLoopback);
    return {
      case: "historical-request-lookup-ignored", outcome: "reproduced", policy: "strict defaults",
      adapterCommit: commits.before, coreOverrideCommit: commits.controlledCore,
      policyAnswers: [PUBLIC_ANSWER], assignedPin, policyLookups,
      constructorLookupAnswer: LOOPBACK, constructorLookups, requestLookupCalls, ...server,
    };
  } finally {
    await dispatcher.destroy();
  }
}));

results.push(await withLocalServer(async (origin, server) => {
  const answers = [];
  const dispatcher = after.createSsrfAgent({
    lookup: async (hostname) => {
      assert.equal(hostname, HOSTNAME);
      const answer = answers.length === 0 ? PUBLIC_ANSWER : LOOPBACK;
      answers.push(answer);
      return [answer];
    },
  }, { connections: 1, connectTimeout: 1000 });
  let errorCode;
  try {
    await assert.rejects(dispatcher.request({ origin, path: "/", method: "GET" }), (error) => {
      assert.ok(error instanceof after.HostfenceError);
      assert.ok(error.reasons.some((reason) => reason.includes(LOOPBACK)));
      errorCode = error.code;
      return true;
    });
    assert.deepEqual(answers, [PUBLIC_ANSWER, LOOPBACK]);
    assert.equal(server.sockets, 0);
    assert.equal(server.requests, 0);
    return {
      case: "fixed-connection-time-recheck", outcome: "blocked", policy: "strict defaults",
      adapterCommit: commits.after, coreOverrideCommit: commits.controlledCore,
      policyAnswers: answers, policyLookups: answers.length, errorCode, ...server,
    };
  } finally {
    await dispatcher.destroy();
  }
}));

results.push(await withLocalServer(async (origin, server) => {
  const answers = [];
  const dispatcher = after.createSsrfAgent({
    allowLoopback: true, // Positive control only; not the production default.
    allowedHosts: [HOSTNAME],
    lookup: async (hostname) => {
      assert.equal(hostname, HOSTNAME);
      answers.push(LOOPBACK);
      return [LOOPBACK];
    },
  }, { connections: 1, connectTimeout: 1000 });
  try {
    const response = await dispatcher.request({ origin, path: "/", method: "GET" });
    assert.equal(await response.body.text(), "loopback fixture");
    assert.deepEqual(answers, [LOOPBACK, LOOPBACK]);
    assert.equal(server.sockets, 1);
    assert.equal(server.requests, 1);
    assert.ok(server.hostMatches && server.peersAreLoopback);
    return {
      case: "fixed-pinned-positive-control", outcome: "connected", policy: "explicit test-only allowLoopback",
      adapterCommit: commits.after, coreOverrideCommit: commits.controlledCore,
      policyAnswers: answers, policyLookups: answers.length, ...server,
    };
  } finally {
    await dispatcher.destroy();
  }
}));

console.log(JSON.stringify({
  schemaVersion: 1,
  caseId: "undici-dispatch-vs-connect",
  node: process.version,
  platform: process.platform,
  architecture: process.arch,
  undici: "6.29.0",
  commits,
  experiment: "historical and fixed adapters share an explicit hostfence 1.4.1 override to isolate transport integration; not the historical broken lockfile environment",
  coreResolution: { version: installedCore.version, path: "node_modules/hostfence", sharedModuleIdentity: true },
  installedAdapters,
  fixtureSha256: digest(await readFile(new URL(import.meta.url))),
  lockfileSha256: digest(lockBytes),
  networkModel: "deterministic policy lookups and constructor-level secondary resolver; all real sockets are loopback; no public DNS rebind",
  assertionsPassed: true,
  cases: results,
}, null, 2));
