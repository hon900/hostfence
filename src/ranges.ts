import net from "node:net";

export const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "metadata.azure.com",
  "instance-data",
  "kubernetes.default",
  "kubernetes.default.svc",
  "kubernetes.default.svc.cluster.local",
]);

export function expandIPv6(ip: string): number[] | null {
  if (!net.isIPv6(ip) || ip.includes("%")) return null;
  let value = ip.toLowerCase();
  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    const octets = value.slice(separator + 1).split(".").map(Number);
    value = `${value.slice(0, separator)}:${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`;
  }
  const [head = "", tail] = value.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const parts = tail === undefined
    ? headParts
    : [...headParts, ...Array(8 - headParts.length - tailParts.length).fill("0"), ...tailParts];
  return parts.map((part) => Number.parseInt(part, 16));
}

function v4FromGroups(hi: number, lo: number): string {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

export function ipv4Mapped(ip: string): string | null {
  const groups = expandIPv6(ip);
  if (!groups || groups.slice(0, 5).some((group) => group !== 0) || groups[5] !== 0xffff) {
    return null;
  }
  return v4FromGroups(groups[6]!, groups[7]!);
}

/**
 * IPv4 carried inside IPv6 transition prefixes that SSRF filters must unwrap:
 * IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96, and 6to4 2002::/16.
 */
export function embeddedIPv4(ip: string): string | null {
  const mapped = ipv4Mapped(ip);
  if (mapped) return mapped;
  const groups = expandIPv6(ip);
  if (!groups) return null;
  if (
    groups[0] === 0x64 &&
    groups[1] === 0xff9b &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0
  ) {
    return v4FromGroups(groups[6]!, groups[7]!);
  }
  if (groups[0] === 0x2002) {
    return v4FromGroups(groups[1]!, groups[2]!);
  }
  return null;
}
