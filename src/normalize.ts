import net from "node:net";
import { domainToASCII } from "node:url";

const TRAILING_DOT = /\.+$/;

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
  const unwrapped = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (net.isIPv6(unwrapped) && !unwrapped.includes("%")) {
    return new URL(`http://[${unwrapped}]/`).hostname.slice(1, -1);
  }
  // Use the same WHATWG normalization as URL: IDNA, short IPv4, hex and octal.
  // Reject delimiters here so this hostname helper never parses a URL or userinfo.
  if (host && !/[\s/:?#@\\\[\]]/.test(host)) {
    return normalizeHostname(domainToASCII(host)) || host;
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
