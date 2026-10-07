import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Test the distributable in a fresh consumer, not imports from this checkout.
// Nothing is published; temporary tarballs and node_modules are removed.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const scratch = mkdtempSync(join(tmpdir(), 'hostfence-package-'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const run = (command, args, cwd) => execFileSync(command, args, {
  cwd, encoding: 'utf8', timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'],
});

try {
  const [packed] = JSON.parse(run(npm, ['pack', '--json', '--pack-destination', scratch], root));
  const expected = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  assert.equal(packed.name, 'hostfence');
  assert.equal(packed.version, expected.version);
  assert.equal(typeof packed.integrity, 'string');
  const files = packed.files.map(file => file.path);
  for (const required of ['package.json', 'dist/index.js', 'dist/index.d.ts', 'README.md', 'SECURITY.md', 'LICENSE']) {
    assert.ok(files.includes(required), `Package is missing ${required}`);
  }
  for (const file of files) {
    assert.ok(/^(dist\/[^/]+\.(?:js|d\.ts)|package\.json|README\.md|SECURITY\.md|LICENSE)$/.test(file), `Unexpected packaged file: ${file}`);
  }
  const consumer = join(scratch, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run(npm, ['install', '--offline', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--package-lock=false', join(scratch, packed.filename)], consumer);
  const smoke = `
    import assert from 'node:assert/strict';
    import { Hostfence, HostfenceError, classifyAddress, pinLookup } from 'hostfence';
    const fence = new Hostfence({ lookup: async () => ['1.1.1.1'] });
    assert.equal((await fence.check('https://example.test/')).ok, true);
    await assert.rejects(() => fence.assert('http://127.0.0.1/'), HostfenceError);
    await assert.rejects(() => fence.assert('http://240.0.0.1/'), HostfenceError);
    assert.equal(classifyAddress('0:0:0:0:0:ffff:127.0.0.1'), 'loopback');
    assert.equal(classifyAddress('invalid'), 'invalid');
    const ports = new Hostfence({ allowedPorts: [443], lookup: async () => ['1.1.1.1'] });
    assert.equal((await ports.check('http://example.test/')).ok, false);
    const { pin } = await fence.assertPin('https://8.8.8.8.nip.io/');
    assert.equal(pin.address, '1.1.1.1');
    assert.equal(pin.servername, '8.8.8.8.nip.io');
    await new Promise((resolve, reject) => pinLookup(pin)(pin.servername, { all: true }, (error, addresses) => {
      if (error) return reject(error);
      try { assert.deepEqual(addresses, [{ address: '1.1.1.1', family: 4 }]); resolve(); }
      catch (failure) { reject(failure); }
    }));
    await assert.rejects(() => new Hostfence({ lookup: async () => [] }).assertPin('https://8.8.8.8.nip.io/'), HostfenceError);
  `;
  run(process.execPath, ['--input-type=module', '--eval', smoke], consumer);
  console.log(`Verified ${packed.filename}: ${files.length} files, isolated offline install and policy smoke checks passed.`);
  console.log(`Package integrity: ${packed.integrity}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
