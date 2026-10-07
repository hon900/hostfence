export { HostfenceError } from "./errors.js";
export { Hostfence, createHostfence, type CheckResult } from "./hostfence.js";
export { classifyAddress, type AddressClass } from "./classify.js";
export { canonicalizeHost, dwordToIPv4 } from "./normalize.js";
export { hostnameEmbeddedIPs } from "./hostname-ip.js";
export { embeddedIPv4, ipv4Mapped } from "./ranges.js";
export { pinLookup, makePin, type DestinationPin } from "./pin.js";
export type { HostfencePolicy, LookupFn } from "./policy.js";
