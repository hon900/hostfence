import net from "node:net";

const TRAILING_DOT = /\.$/;

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(TRAILING_DOT, "");
}

export function dwordToIPv4(n: number): string | null {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    return null;
  }
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

/**
 * Collapse unusual host encodings that browsers and some HTTP stacks still accept.
 * Returns a canonical hostname or dotted IP when the input is an address form.
 */
export function canonicalizeHost(hostname: string): string {
  const host = normalizeHostname(hostname);

  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }

  if (/^\d+$/.test(host)) {
    const dotted = dwordToIPv4(Number(host));
    if (dotted) {
      return dotted;
    }
  }

  if (/^0x[0-9a-f]+$/i.test(host)) {
    const dotted = dwordToIPv4(Number.parseInt(host, 16));
    if (dotted) {
      return dotted;
    }
  }

  if (/^0[0-7]+$/.test(host)) {
    const dotted = dwordToIPv4(Number.parseInt(host, 8));
    if (dotted) {
      return dotted;
    }
  }

  if (net.isIP(host)) {
    return host;
  }

  return host;
}

export function isLocalSuffix(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "localhost.localdomain" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan")
  );
}
