export { HostfenceError } from "./errors.js";
export { Hostfence, createHostfence, type CheckResult } from "./hostfence.js";
export { classifyAddress, type AddressClass } from "./classify.js";
export { canonicalizeHost, dwordToIPv4 } from "./normalize.js";
export type { HostfencePolicy, LookupFn } from "./policy.js";
