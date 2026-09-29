import net from "node:net";

export const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
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

export function ipv4Mapped(ip: string): string | null {
  const groups = expandIPv6(ip);
  if (!groups || groups.slice(0, 5).some((group) => group !== 0) || groups[5] !== 0xffff) {
    return null;
  }
  const hi = groups[6]!;
  const lo = groups[7]!;
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}
