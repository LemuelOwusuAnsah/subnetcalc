export type IPv4 = { octets: [number, number, number, number] };

export type SubnetInfo = {
  cidr: number;
  networkAddress: string;
  broadcastAddress: string;
  firstUsable: string | null;
  lastUsable: string | null;
  totalAddresses: number;
  usableHosts: number;
  subnetMask: string;
  wildcardMask: string;
  networkAddressInt: number;
  broadcastAddressInt: number;
  ipClass: 'A' | 'B' | 'C' | 'D' | 'E';
  isPrivate: boolean;
};

export type ParsedInput = {
  ip: string;
  cidr: number;
  ipInt: number;
};

const PRIVATE_RANGES: ReadonlyArray<[number, number]> = [
  [ipToInt('10.0.0.0'), ipToInt('10.255.255.255')],
  [ipToInt('172.16.0.0'), ipToInt('172.31.255.255')],
  [ipToInt('192.168.0.0'), ipToInt('192.168.255.255')],
];

export function ipToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error('invalid IPv4: ' + ip);
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      throw new Error('invalid octet: ' + part);
    }
    n = (n << 8) + octet;
  }
  return n >>> 0;
}

export function intToIp(n: number): string {
  const v = n >>> 0;
  return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

export function parseInput(input: string): ParsedInput {
  const trimmed = input.trim();
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(trimmed);
  if (!m) throw new Error('expected format: a.b.c.d/prefix');
  const ip = m[1];
  const cidr = Number(m[2]);
  if (!ip) throw new Error('missing ip');
  if (!Number.isInteger(cidr) || cidr < 0 || cidr > 32) {
    throw new Error('prefix must be 0-32');
  }
  return { ip, cidr, ipInt: ipToInt(ip) };
}

export function maskFromCidr(cidr: number): number {
  if (cidr === 0) return 0;
  return (0xffffffff << (32 - cidr)) >>> 0;
}

export function wildcardFromCidr(cidr: number): number {
  return (~maskFromCidr(cidr)) >>> 0;
}

export function networkAddress(ipInt: number, cidr: number): number {
  return (ipInt & maskFromCidr(cidr)) >>> 0;
}

export function broadcastAddress(ipInt: number, cidr: number): number {
  return (networkAddress(ipInt, cidr) | wildcardFromCidr(cidr)) >>> 0;
}

export function ipClassFor(n: number): 'A' | 'B' | 'C' | 'D' | 'E' {
  const first = n >>> 24;
  if (first < 128) return 'A';
  if (first < 192) return 'B';
  if (first < 224) return 'C';
  if (first < 240) return 'D';
  return 'E';
}

export function isPrivate(n: number): boolean {
  for (const range of PRIVATE_RANGES) {
    const lo = range[0];
    const hi = range[1];
    if (lo === undefined || hi === undefined) continue;
    if (n >= lo && n <= hi) return true;
  }
  return false;
}

export function analyze(input: string): SubnetInfo {
  const { cidr, ipInt } = parseInput(input);
  const net = networkAddress(ipInt, cidr);
  const bcast = broadcastAddress(ipInt, cidr);
  const total = Math.pow(2, 32 - cidr);
  const usable = cidr >= 31 ? (cidr === 32 ? 1 : 2) : total - 2;
  const first = cidr === 32 ? net : cidr === 31 ? net : net + 1;
  const last = cidr === 32 ? net : cidr === 31 ? bcast : bcast - 1;

  return {
    cidr,
    networkAddress: intToIp(net),
    broadcastAddress: intToIp(bcast),
    firstUsable: intToIp(first),
    lastUsable: intToIp(last),
    totalAddresses: total,
    usableHosts: usable,
    subnetMask: intToIp(maskFromCidr(cidr)),
    wildcardMask: intToIp(wildcardFromCidr(cidr)),
    networkAddressInt: net,
    broadcastAddressInt: bcast,
    ipClass: ipClassFor(ipInt),
    isPrivate: isPrivate(ipInt),
  };
}

export type SubnetSlice = {
  index: number;
  cidr: number;
  networkAddress: string;
  broadcastAddress: string;
};

export function split(input: string, newCidr: number): SubnetSlice[] {
  const { cidr, ipInt } = parseInput(input);
  if (newCidr < cidr || newCidr > 32) {
    throw new Error('new prefix must be between ' + cidr + ' and 32');
  }
  const net = networkAddress(ipInt, cidr);
  const blockSize = Math.pow(2, 32 - newCidr);
  const count = Math.pow(2, newCidr - cidr);
  if (count > 4096) {
    throw new Error('too many subnets (' + count + '), max 4096');
  }
  const out: SubnetSlice[] = [];
  for (let i = 0; i < count; i++) {
    const sNet = (net + i * blockSize) >>> 0;
    const sBcast = (sNet + blockSize - 1) >>> 0;
    out.push({
      index: i,
      cidr: newCidr,
      networkAddress: intToIp(sNet),
      broadcastAddress: intToIp(sBcast),
    });
  }
  return out;
}

export function toBinary(ip: string): string {
  const n = ipToInt(ip);
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('.');
}

export function toBinaryWithSplit(ip: string, cidr: number): { network: string; host: string } {
  const bin = toBinary(ip).replace(/\./g, '');
  return {
    network: bin.slice(0, cidr),
    host: bin.slice(cidr),
  };
}
