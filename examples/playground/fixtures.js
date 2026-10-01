// Deterministic examples: the playground never resolves DNS or fetches a target.
export const records = Object.freeze({
  'example.com': ['93.184.215.14'],
  'hooks.example.com': ['1.1.1.1'],
  'mixed.example': ['1.1.1.1', '10.0.0.8'],
  'private.example': ['192.168.1.20'],
  'empty.example': [],
});

export const profiles = Object.freeze({
  default: { label: 'Public internet', description: 'Default protection for user-supplied URLs.', policy: {} },
  webhook: { label: 'Webhook delivery', description: 'HTTPS on port 443, only hooks.example.com.', policy: { protocols: ['https'], allowedPorts: [443], allowedHosts: ['hooks.example.com'] } },
});

export const scenarios = [
  { id: 'public', name: 'Public website', category: 'Allowed', url: 'https://example.com/articles', expected: true, detail: 'All fixture addresses are public.' },
  { id: 'metadata', name: 'Cloud metadata', category: 'Metadata', url: 'http://169.254.169.254/latest/meta-data/', expected: false, detail: 'A link-local address used by instance metadata services.' },
  { id: 'decimal', name: 'Encoded loopback', category: 'Encoding', url: 'http://2130706433/admin', expected: false, detail: 'The URL parser normalizes decimal 2130706433 to 127.0.0.1.' },
  { id: 'mapped', name: 'IPv4 inside IPv6', category: 'IPv6', url: 'http://[::ffff:127.0.0.1]/', expected: false, detail: 'An IPv4-mapped IPv6 address still points at loopback.' },
  { id: 'mixed', name: 'Mixed DNS answers', category: 'DNS', url: 'https://mixed.example/', expected: false, detail: 'One public answer does not make a private answer acceptable.' },
  { id: 'private', name: 'Private network', category: 'Private', url: 'https://private.example/dashboard', expected: false, detail: 'This fixture resolves to an RFC1918 network address.' },
  { id: 'protocol', name: 'Unexpected protocol', category: 'Protocol', url: 'gopher://example.com/', expected: false, detail: 'Only HTTP and HTTPS are allowed by default.' },
  { id: 'reserved', name: 'Reserved address', category: 'Reserved', url: 'http://240.0.0.1/', expected: false, detail: 'Reserved IPv4 space is not a public request destination.' },
  { id: 'empty', name: 'Empty DNS answer', category: 'DNS', url: 'https://empty.example/', expected: false, detail: 'The absence of addresses cannot authorize a request.' },
  { id: 'webhook', name: 'Approved webhook', category: 'Allowed', url: 'https://hooks.example.com/events', expected: true, detail: 'Try the webhook policy to constrain the protocol, host and port.' },
];

export async function fixtureLookup(hostname) {
  if (!Object.hasOwn(records, hostname)) {
    throw new Error('No demo DNS record for this hostname. Try example.com, hooks.example.com or an IP literal.');
  }
  return [...records[hostname]];
}
