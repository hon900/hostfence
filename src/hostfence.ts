import net from "node:net";
import { HostfenceError } from "./errors.js";
import { extraCidrList, classBlocked, classifyAddress } from "./classify.js";
import { hostnameEmbeddedIPs } from "./hostname-ip.js";
import { defaultLookup, lookupWithTimeout } from "./lookup.js";
import { canonicalizeHost, isLocalSuffix, normalizeHostname } from "./normalize.js";
import { effectivePort, makePin, type DestinationPin } from "./pin.js";
import { resolvePolicy, type HostfencePolicy, type ResolvedPolicy } from "./policy.js";
import { METADATA_HOSTS, embeddedIPv4, ipv4Mapped } from "./ranges.js";

export type CheckResult = {
  ok: boolean;
  url: URL;
  hostname: string;
  addresses: string[];
  /** Set when every collected address is allowed. Bind the TCP connection to this. */
  pin: DestinationPin | null;
  reasons: string[];
};

export class Hostfence {
  readonly policy: ResolvedPolicy;
  private readonly extraDenied;

  constructor(policy: HostfencePolicy = {}) {
    this.policy = resolvePolicy(policy);
    this.extraDenied = extraCidrList(this.policy.extraDeniedCidrs);
  }

  async check(input: string | URL): Promise<CheckResult> {
    const reasons: string[] = [];
    let url: URL;
    try {
      url = input instanceof URL ? new URL(input.toString()) : new URL(input);
    } catch {
      throw new HostfenceError(String(input), ["invalid URL"], "HOSTFENCE_INVALID_URL");
    }

    const protocol = url.protocol.replace(/:$/, "").toLowerCase();
    if (!this.policy.protocols.has(protocol)) {
      reasons.push(`protocol ${protocol} is not allowed`);
    }
    if (!this.policy.allowCredentials && (url.username || url.password)) {
      reasons.push("URL credentials are not allowed");
    }
    const port = effectivePort(url, protocol);
    if (this.policy.allowedPorts) {
      if (port === undefined || !this.policy.allowedPorts.has(port)) {
        reasons.push(`port ${port ?? "unspecified"} is not allowed`);
      }
    }

    const hostname = canonicalizeHost(url.hostname);
    const normalized = normalizeHostname(hostname);
    if (!normalized) reasons.push("URL must have a hostname");
    if (normalized) url.hostname = net.isIPv6(normalized) ? `[${normalized}]` : normalized;

    if (this.policy.extraDeniedHosts.has(normalized)) {
      reasons.push("hostname is on the deny list");
    }

    if (METADATA_HOSTS.has(normalized) && !this.policy.allowMetadata) {
      reasons.push("cloud metadata hostname");
    }

    if (isLocalSuffix(normalized) && !this.policy.allowLoopback) {
      reasons.push("localhost-style hostname");
    }

    if (this.policy.allowedHosts && !this.policy.allowedHosts.has(normalized)) {
      reasons.push("hostname is not on the allow list");
    }

    const encoded = hostnameEmbeddedIPs(normalized);
    let addresses: string[] = net.isIP(hostname) ? [hostname] : [...encoded];
    const encodedBlocked = encoded.some((ip) => {
      const cls = classifyAddress(ip);
      return cls === "invalid" || classBlocked(cls, this.policy) !== null;
    });

    const skipDns = net.isIP(hostname) || reasons.length > 0 || encodedBlocked;
    if (!skipDns) {
      try {
        const lookup = this.policy.lookup ?? defaultLookup;
        const records = await lookupWithTimeout(lookup, normalized, this.policy.lookupTimeoutMs);
        if (!Array.isArray(records) || Array.from(records).some((address) => typeof address !== "string")) {
          reasons.push("DNS lookup returned an invalid address list");
        } else {
          addresses = [...new Set([...addresses, ...records])];
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        reasons.push(`DNS lookup failed: ${message}`);
      }
    }

    if (addresses.length === 0 && reasons.length === 0) {
      reasons.push("hostname resolved to no addresses");
    }

    const allowedAddresses: string[] = [];
    for (const address of addresses) {
      const cls = classifyAddress(address);
      if (cls === "invalid") {
        reasons.push("DNS lookup returned an invalid IP address");
        continue;
      }
      if (this.matchesExtraDenied(address)) {
        reasons.push(`${address} matches an extra denied CIDR`);
        continue;
      }
      const blocked = classBlocked(cls, this.policy);
      if (blocked) {
        reasons.push(`${address} is a ${blocked}`);
        continue;
      }
      allowedAddresses.push(address);
    }

    const uniqueReasons = [...new Set(reasons)];
    const ok = uniqueReasons.length === 0;
    const pin =
      ok && allowedAddresses[0] !== undefined && port !== undefined
        ? makePin(allowedAddresses[0], port, normalized)
        : null;

    return {
      ok,
      url,
      hostname: normalized,
      addresses,
      pin,
      reasons: uniqueReasons,
    };
  }

  async assert(input: string | URL): Promise<URL> {
    const result = await this.check(input);
    if (!result.ok) {
      throw new HostfenceError(result.url.toString(), result.reasons);
    }
    return result.url;
  }

  async assertPin(input: string | URL): Promise<{ url: URL; pin: DestinationPin }> {
    const result = await this.check(input);
    if (!result.ok) {
      throw new HostfenceError(result.url.toString(), result.reasons);
    }
    if (!result.pin) {
      throw new HostfenceError(result.url.toString(), ["no pinable destination address"], "HOSTFENCE_NO_PIN");
    }
    return { url: result.url, pin: result.pin };
  }

  /** Validate a redirect Location against the same policy, resolving relative hops. */
  async checkHop(from: string | URL, location: string): Promise<CheckResult> {
    const base = from instanceof URL ? from : new URL(from);
    return this.check(new URL(location, base));
  }

  private matchesExtraDenied(address: string): boolean {
    const unwrapped = embeddedIPv4(address) ?? address;
    const originalFamily = ipv4Mapped(address) ? "ipv4" : net.isIPv6(address) ? "ipv6" : "ipv4";
    const unwrappedFamily = net.isIPv6(unwrapped) ? "ipv6" : "ipv4";
    return this.extraDenied.check(unwrapped, unwrappedFamily) || this.extraDenied.check(address, originalFamily);
  }
}

export function createHostfence(policy: HostfencePolicy = {}): Hostfence {
  return new Hostfence(policy);
}
