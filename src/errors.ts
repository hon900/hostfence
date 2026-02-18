export class HostfenceError extends Error {
  readonly code: string;
  readonly reasons: readonly string[];
  readonly url: string;

  constructor(url: string, reasons: readonly string[], code = "HOSTFENCE_BLOCKED") {
    super(`hostfence blocked ${url}: ${reasons.join("; ")}`);
    this.name = "HostfenceError";
    this.code = code;
    this.reasons = reasons;
    this.url = url;
  }
}
