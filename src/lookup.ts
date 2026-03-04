import { lookup as dnsLookup } from "node:dns/promises";
import net from "node:net";
import type { LookupFn } from "./policy.js";

export const defaultLookup: LookupFn = async (hostname) => {
  if (net.isIP(hostname)) {
    return [hostname];
  }
  const records = await dnsLookup(hostname, { all: true, verbatim: true });
  return records.map((r) => r.address);
};
