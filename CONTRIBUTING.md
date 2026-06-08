# Contributing

Bug reports and pull requests are welcome for tests, docs, and extra
encodings that still sneak past the URL parser.

## Development

```bash
npm install
npm test
```

Node.js 18.18 or later is required.

## SSRF bypass reports

Do not send bypasses in a public pull request. Follow [SECURITY.md](SECURITY.md)
and wait for the Security Maintainer (@hon900) to open a coordinated patch.

## Tests

Add a case under `test/` for every new hostname encoding or address class.
Inject `lookup` on `Hostfence` so unit tests do not hit the network.
