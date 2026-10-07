import net from "node:net";

const LOOPBACK_ZONES = ["localtest.me", "lvh.me", "vcap.me"];

const WILDCARD_ZONES = ["nip.io", "sslip.io", "xip.io"];

function zoneOf(hostname: string, zone: string): boolean {
  return hostname === zone || hostname.endsWith(`.${zone}`);
}

/**
 * IPs that some public wildcard DNS products encode in the hostname itself.
 * These are policy evidence for early rejection, never verified DNS answers
 * or connection destinations. Allowed names still require a DNS lookup.
 */
export function hostnameEmbeddedIPs(hostname: string): string[] {
  const host = hostname.toLowerCase();
  if (!host) return [];

  for (const zone of LOOPBACK_ZONES) {
    if (zoneOf(host, zone)) return ["127.0.0.1"];
  }

  for (const zone of WILDCARD_ZONES) {
    if (!zoneOf(host, zone)) continue;

    const dotted = host.match(/(?:^|\.)((?:\d{1,3}\.){3}\d{1,3})\.[a-z0-9.]+$/);
    if (dotted?.[1] && net.isIPv4(dotted[1])) return [dotted[1]];

    const dashed = host.match(/(?:^|\.)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.[a-z0-9.]+$/);
    if (dashed) {
      const ip = `${dashed[1]}.${dashed[2]}.${dashed[3]}.${dashed[4]}`;
      if (net.isIPv4(ip)) return [ip];
    }
  }

  return [];
}
