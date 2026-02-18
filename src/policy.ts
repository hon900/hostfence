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
  extraDeniedCidrs: string[];
  extraDeniedHosts: Set<string>;
  allowedHosts: Set<string> | null;
  lookup: LookupFn | undefined;
};

export function resolvePolicy(input: HostfencePolicy = {}): ResolvedPolicy {
  const protocols = new Set((input.protocols ?? ["http", "https"]).map((p) => p.toLowerCase()));
  return {
    protocols,
    allowPrivate: input.allowPrivate === true,
    allowLoopback: input.allowLoopback === true,
    allowLinkLocal: input.allowLinkLocal === true,
    allowUniqueLocal: input.allowUniqueLocal === true,
    allowMetadata: input.allowMetadata === true,
    allowCgnat: input.allowCgnat === true,
    extraDeniedCidrs: input.extraDeniedCidrs ? [...input.extraDeniedCidrs] : [],
    extraDeniedHosts: new Set((input.extraDeniedHosts ?? []).map((h) => h.toLowerCase())),
    allowedHosts: input.allowedHosts
      ? new Set(input.allowedHosts.map((h) => h.toLowerCase()))
      : null,
    lookup: input.lookup,
  };
}
