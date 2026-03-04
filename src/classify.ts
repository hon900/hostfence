import { BlockList } from "node:net";
import net from "node:net";
import { ipv4Mapped } from "./ranges.js";
import type { ResolvedPolicy } from "./policy.js";

function parseCidr(cidr: string): { addr: string; prefix: number; kind: "ipv4" | "ipv6" } | null {
  const [addr, bits] = cidr.split("/");
  if (!addr || bits === undefined) {
    return null;
  }
  const prefix = Number(bits);
  if (net.isIPv4(addr) && prefix >= 0 && prefix <= 32) {
    return { addr, prefix, kind: "ipv4" };
  }
  if (net.isIPv6(addr) && prefix >= 0 && prefix <= 128) {
    return { addr, prefix, kind: "ipv6" };
  }
  return null;
}

export function extraCidrList(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    if (parsed) {
      list.addSubnet(parsed.addr, parsed.prefix, parsed.kind);
    }
  }
  return list;
}

export type AddressClass =
  | "public"
  | "loopback"
  | "private"
  | "link-local"
  | "cgnat"
  | "unique-local"
  | "unspecified"
  | "multicast"
  | "documentation"
  | "metadata";

export function classifyAddress(ip: string): AddressClass {
  const mapped = ipv4Mapped(ip);
  const v4 = mapped ?? (net.isIPv4(ip) ? ip : null);
  if (v4) {
    if (v4 === "100.100.100.200") return "metadata";
    if (inV4(v4, "127.0.0.0", 8) || v4 === "0.0.0.0") return "loopback";
    if (inV4(v4, "169.254.0.0", 16)) return "link-local";
    if (inV4(v4, "100.64.0.0", 10)) return "cgnat";
    if (
      inV4(v4, "10.0.0.0", 8) ||
      inV4(v4, "172.16.0.0", 12) ||
      inV4(v4, "192.168.0.0", 16)
    ) {
      return "private";
    }
    if (inV4(v4, "224.0.0.0", 4) || v4 === "255.255.255.255") return "multicast";
    if (
      inV4(v4, "192.0.2.0", 24) ||
      inV4(v4, "198.51.100.0", 24) ||
      inV4(v4, "203.0.113.0", 24) ||
      inV4(v4, "198.18.0.0", 15) ||
      inV4(v4, "192.0.0.0", 24)
    ) {
      return "documentation";
    }
    if (inV4(v4, "0.0.0.0", 8)) return "unspecified";
    return "public";
  }

  if (!net.isIPv6(ip)) {
    return "public";
  }
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return "unspecified";
  if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return "loopback";
  if (inV6Prefix(ip, "fe80::", 10)) return "link-local";
  if (inV6Prefix(ip, "fc00::", 7)) return "unique-local";
  if (inV6Prefix(ip, "ff00::", 8)) return "multicast";
  if (inV6Prefix(ip, "2001:db8::", 32)) return "documentation";
  return "public";
}

function inV4(ip: string, base: string, prefix: number): boolean {
  const list = new BlockList();
  list.addSubnet(base, prefix, "ipv4");
  return list.check(ip, "ipv4");
}

function inV6Prefix(ip: string, base: string, prefix: number): boolean {
  const list = new BlockList();
  list.addSubnet(base, prefix, "ipv6");
  return list.check(ip, "ipv6");
}

export function classBlocked(kind: AddressClass, policy: ResolvedPolicy): string | null {
  switch (kind) {
    case "public":
      return null;
    case "loopback":
      return policy.allowLoopback ? null : "loopback address";
    case "private":
      return policy.allowPrivate ? null : "private address";
    case "link-local":
      return policy.allowLinkLocal ? null : "link-local address";
    case "cgnat":
      return policy.allowCgnat ? null : "shared/CGNAT address";
    case "unique-local":
      return policy.allowUniqueLocal ? null : "IPv6 unique-local address";
    case "unspecified":
      return "unspecified address";
    case "multicast":
      return "multicast/broadcast address";
    case "documentation":
      return "documentation/benchmark address";
    case "metadata":
      return policy.allowMetadata ? null : "cloud metadata address";
  }
}
