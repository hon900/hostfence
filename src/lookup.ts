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

/** Bounds the wait; it cannot cancel an OS lookup or a custom resolver. */
export async function lookupWithTimeout(lookup: LookupFn, hostname: string, timeoutMs: number): Promise<string[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(() => lookup(hostname)),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
