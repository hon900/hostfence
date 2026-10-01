import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { request } from 'node:http';
import { createPlaygroundServer } from '../examples/playground/server.js';
import { scenarios } from '../examples/playground/fixtures.js';

// Exercise the real local HTTP boundary; fixture targets are never contacted.
describe('local policy playground', () => {
  let server;
  let port;
  let origin;

  before(async () => {
    server = createPlaygroundServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    port = server.address().port;
    origin = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (!server?.listening) return;
    await new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  });

  function http({ method = 'GET', path = '/', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
      const req = request({ hostname: '127.0.0.1', port, method, path, agent: false, headers }, res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('error', reject);
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try { json = JSON.parse(text); } catch { /* Static assets are not JSON. */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      });
      req.setTimeout(3000, () => req.destroy(new Error('Local playground request timed out')));
      req.on('error', reject);
      if (Array.isArray(body)) {
        for (const chunk of body) req.write(chunk);
        req.end();
      } else req.end(body);
    });
  }

  function check(url, profile = 'default', headers = {}) {
    return http({ method: 'POST', path: '/api/check', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify({ url, profile }) });
  }

  for (const scenario of scenarios) {
    it(`matches the default ${scenario.id} fixture decision`, async () => {
      const result = await check(scenario.url);
      assert.equal(result.status, 200);
      assert.equal(result.json.ok, scenario.expected);
      assert.equal(result.json.mode, 'fixture');
      assert.equal(result.json.profile, 'default');
      assert.equal(typeof result.json.durationMs, 'number');
      assert.ok(Number.isFinite(result.json.durationMs));
      assert.equal(result.json.classifications.length, result.json.addresses.length);
      assert.equal(result.json.reasons.length === 0, scenario.expected);
    });
  }

  it('exposes the fixture catalog without policy internals', async () => {
    const result = await http({ path: '/api/scenarios' });
    assert.equal(result.status, 200);
    assert.deepEqual(result.json.scenarios.map(item => item.id), scenarios.map(item => item.id));
    assert.deepEqual(Object.keys(result.json.profiles).sort(), ['default', 'webhook']);
    assert.equal(result.json.profiles.webhook.policy, undefined);
  });

  it('allows the webhook host with HTTPS and its implicit port', async () => {
    const result = await check('https://hooks.example.com/events', 'webhook');
    assert.equal(result.status, 200);
    assert.equal(result.json.ok, true);
    assert.deepEqual(result.json.addresses, ['1.1.1.1']);
  });

  for (const [url, reason] of [
    ['https://example.com/events', /allow list/],
    ['https://hooks.example.com.attacker.invalid/events', /allow list/],
    ['http://hooks.example.com/events', /protocol http/],
    ['https://hooks.example.com:8443/events', /port 8443/],
    ['https://1.1.1.1/events', /allow list/],
  ]) {
    it(`enforces webhook policy for ${url}`, async () => {
      const result = await check(url, 'webhook');
      assert.equal(result.status, 200);
      assert.equal(result.json.ok, false);
      assert.match(result.json.reasons.join('; '), reason);
    });
  }

  it('reports mixed DNS answers and their classifications', async () => {
    const result = await check('https://mixed.example/');
    assert.equal(result.json.ok, false);
    assert.deepEqual(result.json.classifications, [
      { address: '1.1.1.1', kind: 'public' },
      { address: '10.0.0.8', kind: 'private' },
    ]);
  });

  it('fails closed for a hostname absent from the fixture map', async () => {
    const result = await check('https://attacker.invalid/');
    assert.equal(result.status, 200);
    assert.equal(result.json.ok, false);
    assert.deepEqual(result.json.addresses, []);
    assert.match(result.json.reasons.join('; '), /No demo DNS record/);
  });

  it('returns structured invalid-URL errors without reflecting raw input', async () => {
    const result = await check('http://owner:super-secret@');
    assert.equal(result.status, 200);
    assert.equal(result.json.ok, false);
    assert.equal(result.json.code, 'HOSTFENCE_INVALID_URL');
    assert.equal(result.json.url, '(invalid URL)');
    assert.ok(!result.text.includes('super-secret'));
  });

  it('redacts credentials in valid rejected URLs', async () => {
    const result = await check('https://owner:super-secret@example.com/');
    assert.equal(result.json.ok, false);
    assert.equal(result.json.url, 'https://redacted@example.com/');
    assert.match(result.json.reasons.join('; '), /credentials/);
    assert.ok(!result.text.includes('owner'));
    assert.ok(!result.text.includes('super-secret'));
  });

  for (const body of ['{', 'null', '[]', '"text"', '{}', '{"url":42}']) {
    it(`rejects malformed request body ${body}`, async () => {
      const result = await http({ method: 'POST', path: '/api/check', headers: { 'Content-Type': 'application/json' }, body });
      assert.equal(result.status, 400);
      assert.equal(typeof result.json.error, 'string');
    });
  }

  for (const profile of ['unknown', '__proto__', 'constructor', 'toString']) {
    it(`rejects unknown or inherited profile ${profile}`, async () => {
      assert.equal((await check('https://example.com/', profile)).status, 400);
    });
  }

  for (const profile of [['default'], {}, { toString: null }, 42, true]) {
    it(`rejects a non-string policy profile ${JSON.stringify(profile)}`, async () => {
      const result = await check('https://example.com/', profile);
      assert.equal(result.status, 400);
      assert.equal(typeof result.json.error, 'string');
    });
  }

  it('rejects a URL over the input length cap', async () => {
    assert.equal((await check(`https://example.com/${'a'.repeat(2048)}`)).status, 400);
  });

  it('rejects an oversized body by bytes even with chunked input', async () => {
    const result = await http({
      method: 'POST', path: '/api/check', headers: { 'Content-Type': 'application/json' },
      body: ['{"url":"', '🌐'.repeat(2200), '"}'],
    });
    assert.equal(result.status, 413);
    assert.match(result.json.error, /too large/);
    assert.equal((await check('https://example.com/')).json.ok, true);
  });

  it('requires a JSON media type', async () => {
    const result = await http({ method: 'POST', path: '/api/check', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
    assert.equal(result.status, 415);
  });

  it('accepts JSON with a charset parameter and a matching Origin', async () => {
    const result = await check('https://example.com/', 'default', { 'Content-Type': 'application/json; charset=utf-8', Origin: origin });
    assert.equal(result.status, 200);
    assert.equal(result.json.ok, true);
  });

  for (const badOrigin of ['https://attacker.invalid', 'null', 'http://localhost:4317']) {
    it(`rejects cross-origin requests from ${badOrigin}`, async () => {
      const result = await check('https://example.com/', 'default', { Origin: badOrigin });
      assert.equal(result.status, 403);
      assert.equal(result.headers['access-control-allow-origin'], undefined);
    });
  }

  for (const host of ['attacker.invalid', '127.0.0.1', 'localhost:4317']) {
    it(`rejects an unexpected Host header ${host}`, async () => {
      assert.equal((await http({ headers: { Host: host } })).status, 403);
    });
  }

  it('serves only explicit assets with browser security headers', async () => {
    for (const [path, contentType] of [['/', /text\/html/], ['/app.js', /text\/javascript/], ['/style.css', /text\/css/]]) {
      const result = await http({ path });
      assert.equal(result.status, 200);
      assert.match(result.headers['content-type'], contentType);
      assert.equal(result.headers['cache-control'], 'no-store');
      assert.equal(result.headers['x-content-type-options'], 'nosniff');
      assert.equal(result.headers['referrer-policy'], 'no-referrer');
      assert.match(result.headers['content-security-policy'], /frame-ancestors 'none'/);
      assert.match(result.headers['content-security-policy'], /connect-src 'self'/);
    }
  });

  for (const path of ['/../../package.json', '/%2e%2e/%2e%2e/package.json', '/public/../server.js', '/server.js', '/fixtures.js', '/.env']) {
    it(`does not serve files through ${path}`, async () => {
      const result = await http({ path });
      assert.equal(result.status, 404);
      assert.deepEqual(result.json, { error: 'Not found.' });
    });
  }

  it('does not accept unsupported methods on the check endpoint', async () => {
    assert.equal((await http({ path: '/api/check' })).status, 404);
    assert.equal((await http({ method: 'OPTIONS', path: '/api/check' })).status, 404);
  });
});
