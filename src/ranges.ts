import net, { BlockList } from "node:net";

export type IpKind = "ipv4" | "ipv6";

export const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata.azure.com",
  "instance-data",
  "kubernetes.default",
  "kubernetes.default.svc",
  "kubernetes.default.svc.cluster.local",
]);

const V4_PRIVATE: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["255.255.255.255", 32],
];

const V6_PRIVATE: Array<[string, number]> = [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["2001:db8::", 32],
];

export function createDefaultBlockList(): BlockList {
  const list = new BlockList();
  for (const [addr, prefix] of V4_PRIVATE) {
    list.addSubnet(addr, prefix, "ipv4");
  }
  for (const [addr, prefix] of V6_PRIVATE) {
    list.addSubnet(addr, prefix, "ipv6");
  }
  list.addAddress("100.100.100.200", "ipv4");
  return list;
}

export function expandIPv6(ip: string): number[] | null {
  const lower = ip.toLowerCase();
  if (!net.isIPv6(lower) && !lower.startsWith("::ffff:")) {
    return null;
  }
  const dotted = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted?.[1]) {
    const v4 = dotted[1].split(".").map((n) => Number(n));
    if (v4.length !== 4 || v4.some((n) => n > 255)) {
      return null;
    }
    return [0, 0, 0, 0, 0, 0xffff, (v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!];
  }
  const [head, tail] = lower.split("::");
  const headParts = head ? head.split(":").filter(Boolean) : [];
  const tailParts = tail ? tail.split(":").filter(Boolean) : [];
  if (headParts.length + tailParts.length > 8) {
    return null;
  }
  const missing = 8 - headParts.length - tailParts.length;
  const parts = [...headParts, ...Array(missing).fill("0"), ...tailParts];
  if (parts.length !== 8) {
    return null;
  }
  return parts.map((p) => Number.parseInt(p, 16));
}

export function ipv4Mapped(ip: string): string | null {
  const groups = expandIPv6(ip);
  if (!groups) {
    return null;
  }
  const mapped =
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff;
  if (!mapped) {
    return null;
  }
  const hi = groups[6] ?? 0;
  const lo = groups[7] ?? 0;
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}
