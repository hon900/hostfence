import net, { BlockList } from "node:net";
import { embeddedIPv4, ipv4Mapped } from "./ranges.js";
import type { ResolvedPolicy } from "./policy.js";

export function extraCidrList(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const match = /^([^/]+)\/(0|[1-9]\d*)$/.exec(cidr);
    const address = match?.[1] ?? "";
    const prefix = Number(match?.[2]);
    const family = net.isIP(address);
    if (!match || address.includes("%") || !family || !Number.isInteger(prefix) || prefix > (family === 4 ? 32 : 128)) {
      throw new TypeError(`Invalid denied CIDR: ${cidr}`);
    }
    const kind = family === 4 ? "ipv4" : "ipv6";
    list.addSubnet(address, prefix, kind);
    if (kind === "ipv4") {
      list.addSubnet(`::ffff:${address}`, prefix + 96, "ipv6");
    } else {
      const mapped = ipv4Mapped(address);
      const hostBits = 128 - prefix;
      if (mapped && hostBits <= 32) {
        list.addSubnet(mapped, 32 - hostBits, "ipv4");
      }
    }
  }
  return list;
}

export type AddressClass =
  | "public"
  | "invalid"
  | "reserved"
  | "loopback"
  | "private"
  | "link-local"
  | "cgnat"
  | "unique-local"
  | "unspecified"
  | "multicast"
  | "documentation"
  | "metadata";

type Range = [address: string, prefix: number];

// Build these once, rather than rebuilding BlockList objects for every address.
// Special-purpose ranges: https://www.iana.org/assignments/iana-ipv4-special-registry/
// and https://www.iana.org/assignments/iana-ipv6-special-registry/.
const ADDRESS_RANGES: Array<[AddressClass, BlockList]> = (
  [
    ["metadata", [
      ["100.100.100.200", 32],
      ["168.63.129.16", 32],
      ["fd00:ec2::254", 128],
    ]],
    ["unspecified", [["0.0.0.0", 8], ["::", 128]]],
    ["loopback", [["127.0.0.0", 8], ["::1", 128]]],
    ["link-local", [["169.254.0.0", 16], ["fe80::", 10]]],
    ["cgnat", [["100.64.0.0", 10]]],
    ["private", [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16]]],
    ["unique-local", [["fc00::", 7]]],
    ["multicast", [["224.0.0.0", 4], ["255.255.255.255", 32], ["ff00::", 8]]],
    ["documentation", [["192.0.2.0", 24], ["198.51.100.0", 24], ["203.0.113.0", 24], ["198.18.0.0", 15], ["2001:db8::", 32], ["2001:2::", 48], ["3fff::", 20]]],
    ["reserved", [["192.0.0.0", 24], ["240.0.0.0", 4], ["64:ff9b:1::", 48], ["100::", 64], ["100:0:0:1::", 64], ["5f00::", 16], ["2001::", 32]]],
  ] as Array<[AddressClass, Range[]]>
).map(([kind, ranges]) => {
  const list = new BlockList();
  for (const [address, prefix] of ranges) {
    list.addSubnet(address, prefix, net.isIPv4(address) ? "ipv4" : "ipv6");
  }
  return [kind, list];
});

export function classifyAddress(ip: string): AddressClass {
  if (typeof ip !== "string" || !net.isIP(ip) || ip.includes("%")) return "invalid";
  const address = embeddedIPv4(ip) ?? ip;
  const family = net.isIPv4(address) ? "ipv4" : "ipv6";
  for (const [kind, ranges] of ADDRESS_RANGES) {
    if (ranges.check(address, family)) return kind;
  }
  return "public";
}

export function classBlocked(kind: AddressClass, policy: ResolvedPolicy): string | null {
  switch (kind) {
    case "public": return null;
    case "invalid": return "invalid IP address";
    case "reserved": return "reserved address";
    case "loopback": return policy.allowLoopback ? null : "loopback address";
    case "private": return policy.allowPrivate ? null : "private address";
    case "link-local": return policy.allowLinkLocal ? null : "link-local address";
    case "cgnat": return policy.allowCgnat ? null : "shared/CGNAT address";
    case "unique-local": return policy.allowUniqueLocal ? null : "IPv6 unique-local address";
    case "unspecified": return "unspecified address";
    case "multicast": return "multicast/broadcast address";
    case "documentation": return "documentation/benchmark address";
    case "metadata": return policy.allowMetadata ? null : "cloud metadata address";
  }
}
