import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { Hostfence, HostfenceError, classifyAddress } from '../../dist/index.js';
import { fixtureLookup, profiles, scenarios } from './fixtures.js';

const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const MAX_BODY = 8192;

function send(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}

function readBody(req) {
  return new Promise((done, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) {
        chunks.length = 0;
        reject(Object.assign(new Error('Request body is too large.'), { status: 413 }));
      } else chunks.push(chunk);
    });
    req.on('end', () => done(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function displayUrl(input) {
  try {
    const url = new URL(input);
    if (url.username || url.password) {
      url.username = 'redacted';
      url.password = '';
    }
    return url.toString();
  } catch { return '(invalid URL)'; }
}

export function createPlaygroundServer() {
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const address = server.address();
    const host = `127.0.0.1:${address?.port}`;
    if (req.headers.host !== host || (req.headers.origin && req.headers.origin !== `http://${host}`)) {
      send(res, 403, { error: 'Use the local playground address printed in the terminal.' });
      return;
    }
    const path = req.url?.split('?')[0];
    try {
      if (req.method === 'GET' && assets.has(path)) {
        const [filename, type] = assets.get(path);
        const content = await readFile(new URL(`./public/${filename}`, import.meta.url));
        res.writeHead(200, { 'Content-Type': type });
        res.end(content);
      } else if (req.method === 'GET' && path === '/api/scenarios') {
        send(res, 200, { scenarios, profiles: Object.fromEntries(Object.entries(profiles).map(([id, profile]) => [id, { label: profile.label, description: profile.description }])) });
      } else if (req.method === 'POST' && path === '/api/check') {
        if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
          send(res, 415, { error: 'Send application/json.' });
          return;
        }
        let body;
        try { body = JSON.parse(await readBody(req)); }
        catch (error) { send(res, error.status ?? 400, { error: error.status ? error.message : 'Invalid JSON body.' }); return; }
        if (!body || typeof body.url !== 'string' || body.url.length > 2048 || typeof (body.profile ?? 'default') !== 'string' || !Object.hasOwn(profiles, body.profile ?? 'default')) {
          send(res, 400, { error: 'Provide a URL of at most 2048 characters and a known policy profile.' });
          return;
        }
        const profile = body.profile ?? 'default';
        const fence = new Hostfence({ ...profiles[profile].policy, lookup: fixtureLookup });
        const start = performance.now();
        try {
          const result = await fence.check(body.url);
          send(res, 200, {
            ...result,
            url: displayUrl(result.url),
            classifications: result.addresses.map(address => ({ address, kind: classifyAddress(address) })),
            profile,
            durationMs: Math.round((performance.now() - start) * 100) / 100,
            mode: 'fixture',
          });
        } catch (error) {
          if (!(error instanceof HostfenceError)) throw error;
          send(res, 200, { ok: false, url: displayUrl(body.url), hostname: '', addresses: [], classifications: [], reasons: [...error.reasons], code: error.code, profile, mode: 'fixture', durationMs: Math.round((performance.now() - start) * 100) / 100 });
        }
      } else {
        send(res, 404, { error: 'Not found.' });
      }
    } catch {
      if (!res.headersSent) send(res, 500, { error: 'The playground could not complete the request.' });
      else res.end();
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4317);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be an integer between 0 and 65535.');
  const server = createPlaygroundServer();
  server.on('error', error => { console.error(`Playground: ${error.message}`); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => {
    console.log(`Hostfence playground: http://127.0.0.1:${server.address().port}`);
    console.log('Local fixtures only. No external DNS queries or HTTP requests.');
  });
}
