import net from "node:net";
import { HostfenceError } from "./errors.js";
import { extraCidrList, classBlocked, classifyAddress } from "./classify.js";
import { defaultLookup, lookupWithTimeout } from "./lookup.js";
import { canonicalizeHost, isLocalSuffix, normalizeHostname } from "./normalize.js";
import { resolvePolicy, type HostfencePolicy, type ResolvedPolicy } from "./policy.js";
import { METADATA_HOSTS, ipv4Mapped } from "./ranges.js";

export type CheckResult = {
  ok: boolean;
  url: URL;
  hostname: string;
  addresses: string[];
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
    if (this.policy.allowedPorts) {
      const defaultPorts: Record<string, number> = { http: 80, https: 443, ws: 80, wss: 443, ftp: 21 };
      const port = url.port ? Number(url.port) : defaultPorts[protocol];
      if (port === undefined || !this.policy.allowedPorts.has(port)) {
        reasons.push(`port ${port ?? "unspecified"} is not allowed`);
      }
    }

    const hostname = canonicalizeHost(url.hostname);
    const normalized = normalizeHostname(hostname);
    if (!normalized) reasons.push("URL must have a hostname");
    // Return the same normalized hostname that was checked to the caller.
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

    let addresses: string[] = [];
    if (net.isIP(hostname)) {
      addresses = [hostname];
    } else if (reasons.length === 0) {
      try {
        const lookup = this.policy.lookup ?? defaultLookup;
        const records = await lookupWithTimeout(lookup, normalized, this.policy.lookupTimeoutMs);
        if (!Array.isArray(records) || Array.from(records).some((address) => typeof address !== "string")) {
          reasons.push("DNS lookup returned an invalid address list");
        } else {
          addresses = [...new Set(records)];
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        reasons.push(`DNS lookup failed: ${message}`);
      }
    }

    if (addresses.length === 0 && reasons.length === 0) {
      reasons.push("hostname resolved to no addresses");
    }

    for (const address of addresses) {
      const cls = classifyAddress(address);
      if (cls === "invalid") {
        reasons.push("DNS lookup returned an invalid IP address");
        continue;
      }
      const mapped = ipv4Mapped(address);
      const checkIp = mapped ?? address;
      const kind = net.isIPv6(checkIp) && !mapped ? "ipv6" : "ipv4";
      if (this.extraDenied.check(checkIp, kind)) {
        reasons.push(`${address} matches an extra denied CIDR`);
        continue;
      }
      const blocked = classBlocked(cls, this.policy);
      if (blocked) {
        reasons.push(`${address} is a ${blocked}`);
      }
    }

    return {
      ok: reasons.length === 0,
      url,
      hostname: normalized,
      addresses,
      reasons: [...new Set(reasons)],
    };
  }

  async assert(input: string | URL): Promise<URL> {
    const result = await this.check(input);
    if (!result.ok) {
      throw new HostfenceError(result.url.toString(), result.reasons);
    }
    return result.url;
  }
}

export function createHostfence(policy: HostfencePolicy = {}): Hostfence {
  return new Hostfence(policy);
}
