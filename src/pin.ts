import net from "node:net";

export type DestinationPin = {
  /** Verified destination address to connect to. */
  address: string;
  family: 4 | 6;
  port: number;
  /** Original hostname for TLS SNI and the HTTP Host header. */
  servername: string;
};

export const DEFAULT_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
};

export function effectivePort(url: URL, protocol: string): number | undefined {
  if (url.port) return Number(url.port);
  return DEFAULT_PORTS[protocol];
}

export function makePin(address: string, port: number, servername: string): DestinationPin | null {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (net.isIPv4(address)) {
    return { address, family: 4, port, servername };
  }
  if (net.isIPv6(address)) {
    return { address, family: 6, port, servername };
  }
  return null;
}

type LookupCallback = {
  (err: NodeJS.ErrnoException | null, address: string, family: number): void;
  (err: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>): void;
};

/**
 * Node `dns.lookup`-compatible function that always returns the pinned address.
 * Pass this to undici `Agent({ connect: { lookup } })` so the TCP connection
 * cannot follow a later DNS change.
 */
export function pinLookup(pin: DestinationPin) {
  return function lookup(
    _hostname: string,
    options: unknown,
    callback?: LookupCallback,
  ): void {
    let cb = callback;
    let opts = options as { all?: boolean } | undefined;
    if (typeof options === "function") {
      cb = options as LookupCallback;
      opts = undefined;
    }
    if (!cb) throw new TypeError("pinLookup requires a callback");
    if (opts?.all) {
      cb(null, [{ address: pin.address, family: pin.family }]);
      return;
    }
    cb(null, pin.address, pin.family);
  };
}
