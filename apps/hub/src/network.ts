export type TrustedProxyCidr = {
  address: bigint;
  bits: 32 | 128;
  prefixLength: number;
};

export function readHttpOrigin(value: string | undefined, name: string) {
  if (!value) {
    throw new Error(`${name} is required and must be an HTTP or HTTPS Origin.`);
  }

  // URL normalizes dot paths and empty query/fragment markers. Check the raw
  // deployment value first: an Origin is exactly scheme://authority.
  if (value !== value.trim() || !/^https?:\/\/[^/?#]+$/i.test(value)) {
    throw invalidOrigin(name);
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw invalidOrigin(name);
  }

  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  ) {
    throw invalidOrigin(name);
  }

  return url.origin;
}

export function parseTrustedProxyCidrs(value: string | undefined) {
  if (value === undefined || value.trim() === "") {
    return [];
  }

  return value.split(",").map((entry) => parseTrustedProxyCidr(entry.trim()));
}

export function deriveObservedIp(input: {
  directPeer: string | null;
  trustedProxyCidrs: TrustedProxyCidr[];
  xForwardedFor: string | null;
}) {
  const directPeer = parseIpAddress(input.directPeer);
  if (!directPeer) return null;

  if (
    input.trustedProxyCidrs.length === 0 ||
    !isTrustedProxy(directPeer, input.trustedProxyCidrs)
  ) {
    return directPeer.text;
  }

  const forwarded = parseForwardedFor(input.xForwardedFor);
  if (!forwarded) return directPeer.text;

  for (let index = forwarded.length - 1; index >= 0; index -= 1) {
    const address = forwarded[index]!;
    if (!isTrustedProxy(address, input.trustedProxyCidrs)) {
      return address.text;
    }
  }

  return directPeer.text;
}

export function isNonLoopbackHttpOrigin(origin: string) {
  const url = new URL(origin);
  return url.protocol === "http:" && !isLoopbackHostname(url.hostname);
}

function invalidOrigin(name: string) {
  return new Error(
    `${name} must be an HTTP or HTTPS Origin with only scheme, host, and optional port.`,
  );
}

function parseTrustedProxyCidr(value: string): TrustedProxyCidr {
  const [address, prefix, ...extra] = value.split("/");
  const parsedAddress = parseIpAddress(address ?? null);
  const prefixLength = Number(prefix);

  if (
    !parsedAddress ||
    extra.length > 0 ||
    !/^\d+$/.test(prefix ?? "") ||
    !Number.isInteger(prefixLength) ||
    prefixLength < 0 ||
    prefixLength > parsedAddress.bits
  ) {
    throw new Error(
      "ENOKI_TRUSTED_PROXY_CIDRS must be a comma-separated list of IPv4 or IPv6 CIDRs.",
    );
  }

  return {
    address: parsedAddress.value,
    bits: parsedAddress.bits,
    prefixLength,
  };
}

type ParsedIpAddress = {
  bits: 32 | 128;
  text: string;
  value: bigint;
};

function parseForwardedFor(value: string | null) {
  if (!value) return null;
  const parts = value.split(",").map((part) => part.trim());
  if (parts.length === 0 || parts.some((part) => part === "")) return null;

  const addresses = parts.map((part) => parseIpAddress(part));
  return addresses.every(
    (address): address is ParsedIpAddress => address !== null,
  )
    ? addresses
    : null;
}

function parseIpAddress(value: string | null): ParsedIpAddress | null {
  if (!value) return null;
  const normalized = value.startsWith("::ffff:") ? value.slice(7) : value;
  const ipv4 = parseIpv4(normalized);
  if (ipv4 !== null) {
    return { bits: 32, text: normalized, value: ipv4 };
  }

  const ipv6 = parseIpv6(normalized);
  if (ipv6 === null) return null;
  return { bits: 128, text: normalized.toLowerCase(), value: ipv6 };
}

function parseIpv4(value: string) {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0n;

  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = (result << 8n) | BigInt(octet);
  }

  return result;
}

function parseIpv6(value: string) {
  if (!value || value.includes("%") || value.split("::").length > 2)
    return null;
  const [left, right] = value.split("::");
  const leftParts = left ? left.split(":") : [];
  const rightParts = right ? right.split(":") : [];
  const hasCompression = value.includes("::");
  const parts = [...leftParts, ...rightParts];

  if (
    parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part)) ||
    parts.length > 8 ||
    (!hasCompression && parts.length !== 8) ||
    (hasCompression && parts.length >= 8)
  ) {
    return null;
  }

  const expanded = [
    ...leftParts,
    ...Array.from({ length: 8 - parts.length }, () => "0"),
    ...rightParts,
  ];
  return expanded.reduce(
    (result, part) => (result << 16n) | BigInt(`0x${part}`),
    0n,
  );
}

function isTrustedProxy(address: ParsedIpAddress, cidrs: TrustedProxyCidr[]) {
  return cidrs.some((cidr) => {
    if (cidr.bits !== address.bits) return false;
    if (cidr.prefixLength === 0) return true;
    const shift = BigInt(cidr.bits - cidr.prefixLength);
    return cidr.address >> shift === address.value >> shift;
  });
}

function isLoopbackHostname(hostname: string) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (normalized === "localhost" || normalized === "::1") return true;
  const ipv4 = parseIpv4(normalized);
  if (ipv4 !== null) return ipv4 >> 24n === 127n;

  const ipv6 = parseIpv6(normalized);
  if (ipv6 === null) return false;
  if (ipv6 === 1n) return true;

  const mappedIpv4 = ipv6 & 0xffffffffn;
  return ipv6 >> 32n === 0xffffn && mappedIpv4 >> 24n === 127n;
}
