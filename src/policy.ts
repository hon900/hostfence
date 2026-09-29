import net from "node:net";
import { canonicalizeHost } from "./normalize.js";

export type LookupFn = (hostname: string) => Promise<string[]>;

export type HostfencePolicy = {
  /** Allowed URL protocols. Default: http, https */
  protocols?: string[];
  allowPrivate?: boolean;
  allowLoopback?: boolean;
  allowLinkLocal?: boolean;
  allowUniqueLocal?: boolean;
  allowMetadata?: boolean;
  allowCgnat?: boolean;
  /** Allow URL userinfo. Default: false. */
  allowCredentials?: boolean;
  /** Allowed effective destination ports. Omitted means no port restriction. */
  allowedPorts?: number[];
  /** Maximum time spent awaiting DNS in milliseconds. Default: 5000. */
  lookupTimeoutMs?: number;
  extraDeniedCidrs?: string[];
  extraDeniedHosts?: string[];
  /** When set, only these hostnames (exact match) are allowed after other checks. */
  allowedHosts?: string[];
  lookup?: LookupFn;
};

export type ResolvedPolicy = {
  protocols: Set<string>;
  allowPrivate: boolean;
  allowLoopback: boolean;
  allowLinkLocal: boolean;
  allowUniqueLocal: boolean;
  allowMetadata: boolean;
  allowCgnat: boolean;
  allowCredentials: boolean;
  allowedPorts: Set<number> | null;
  lookupTimeoutMs: number;
  extraDeniedCidrs: string[];
  extraDeniedHosts: Set<string>;
  allowedHosts: Set<string> | null;
  lookup: LookupFn | undefined;
};

export function resolvePolicy(input: HostfencePolicy = {}): ResolvedPolicy {
  const protocols = new Set((input.protocols ?? ["http", "https"]).map((p) => {
    const protocol = p.trim().toLowerCase().replace(/:$/, "");
    if (!/^[a-z][a-z0-9+.-]*$/.test(protocol)) throw new TypeError("Invalid allowed protocol");
    return protocol;
  }));
  const lookupTimeoutMs = input.lookupTimeoutMs ?? 5000;
  if (!Number.isInteger(lookupTimeoutMs) || lookupTimeoutMs < 1 || lookupTimeoutMs > 2147483647) {
    throw new TypeError("lookupTimeoutMs must be an integer between 1 and 2147483647");
  }
  const allowedPorts = input.allowedPorts ? new Set(input.allowedPorts) : null;
  if (allowedPorts && [...allowedPorts].some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
    throw new TypeError("allowedPorts must contain integers between 1 and 65535");
  }
  return {
    protocols,
    allowPrivate: input.allowPrivate === true,
    allowLoopback: input.allowLoopback === true,
    allowLinkLocal: input.allowLinkLocal === true,
    allowUniqueLocal: input.allowUniqueLocal === true,
    allowMetadata: input.allowMetadata === true,
    allowCgnat: input.allowCgnat === true,
    allowCredentials: input.allowCredentials === true,
    allowedPorts,
    lookupTimeoutMs,
    extraDeniedCidrs: input.extraDeniedCidrs ? [...input.extraDeniedCidrs] : [],
    extraDeniedHosts: new Set((input.extraDeniedHosts ?? []).map(policyHostname)),
    allowedHosts: input.allowedHosts
      ? new Set(input.allowedHosts.map(policyHostname))
      : null,
    lookup: input.lookup,
  };
}

function policyHostname(input: string): string {
  const hostname = canonicalizeHost(input);
  if (!net.isIP(hostname) && (!hostname || /[\s/:?#@\\\[\]*%]/.test(hostname))) {
    throw new TypeError("Host policies require exact hostnames or IP addresses, without a scheme, port, or wildcard");
  }
  if (hostname.includes("%")) throw new TypeError("Scoped IP addresses are not supported in host policies");
  return hostname;
}
