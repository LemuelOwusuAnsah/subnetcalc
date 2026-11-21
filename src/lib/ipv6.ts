export type IPv6Analysis = {
  compressed: string;
  expanded: string;
  prefix: number;
  networkAddress: string;
  firstAddress: string;
  lastAddress: string;
  totalAddresses: bigint;
  isPrivate: boolean;
  kind: 'unspecified' | 'loopback' | 'link-local' | 'unique-local' | 'global' | 'multicast';
};

function parseHextets(input: string): number[] {
  const s = input.trim().toLowerCase();
  if (s === '' || s === '::') {
    return new Array(8).fill(0);
  }

  let head = s;
  let tail = '';
  const dc = s.indexOf('::');
  if (dc !== -1) {
    head = s.slice(0, dc);
    tail = s.slice(dc + 2);
  }

  const headParts = head === '' ? [] : head.split(':');
  const tailParts = tail === '' ? [] : tail.split(':');

  const parseParts = (parts: string[]): number[] => {
    const out: number[] = [];
    for (const p of parts) {
      if (p === '') continue;
      if (!/^[0-9a-f]{1,4}$/.test(p)) throw new Error('invalid hextet: ' + p);
      out.push(parseInt(p, 16));
    }
    return out;
  };

  const h = parseParts(headParts);
  const t = parseParts(tailParts);
  const fill = 8 - h.length - t.length;
  if (dc === -1) {
    if (h.length !== 8) throw new Error('IPv6 must have 8 hextets');
    return h;
  }
  if (fill < 0) throw new Error('too many hextets');
  return [...h, ...new Array(fill).fill(0), ...t];
}

function hextetsToBigInt(hextets: number[]): bigint {
  let n = 0n;
  for (const h of hextets) {
    n = (n << 16n) | BigInt(h);
  }
  return n;
}

function bigIntToHextets(n: bigint): number[] {
  const out: number[] = [];
  for (let i = 7; i >= 0; i--) {
    out.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  }
  return out;
}

function compress(hextets: number[]): string {
  const hexes = hextets.map((h) => h.toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let i = 0;
  while (i < 8) {
    if (hextets[i] === 0) {
      let j = i;
      while (j < 8 && hextets[j] === 0) j++;
      if (j - i > bestLen && j - i >= 2) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    } else {
      i++;
    }
  }
  if (bestStart === -1) return hexes.join(':');
  const left = hexes.slice(0, bestStart).join(':');
  const right = hexes.slice(bestStart + bestLen).join(':');
  return left + '::' + right;
}

function expand(hextets: number[]): string {
  return hextets.map((h) => h.toString(16).padStart(4, '0')).join(':');
}

function prefixMask(prefix: number): bigint {
  if (prefix === 0) return 0n;
  const total = 128n;
  let mask = 0n;
  for (let i = 0n; i < prefix; i++) {
    mask |= 1n << (total - 1n - i);
  }
  return mask;
}

export function analyzeIPv6(input: string): IPv6Analysis {
  const s = input.trim();
  const slash = s.lastIndexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const prefixStr = slash === -1 ? '128' : s.slice(slash + 1);
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    throw new Error('prefix must be 0-128');
  }

  const hextets = parseHextets(addr);
  const value = hextetsToBigInt(hextets);

  const mask = prefixMask(prefix);
  const network = value & mask;
  const allOnes = (1n << 128n) - 1n;
  const last = network | (~mask & allOnes);

  const kind: IPv6Analysis['kind'] =
    value === 0n ? 'unspecified' :
    value === 1n ? 'loopback' :
    (value >> 118n) === 0x3fan ? 'link-local' :
    (value >> 121n) === 0x7en ? 'unique-local' :
    (value >> 120n) === 0xffn ? 'multicast' :
    'global';

  return {
    compressed: compress(hextets),
    expanded: expand(hextets),
    prefix,
    networkAddress: compress(bigIntToHextets(network)),
    firstAddress: compress(bigIntToHextets(network)),
    lastAddress: compress(bigIntToHextets(last)),
    totalAddresses: last - network + 1n,
    isPrivate: kind === 'link-local' || kind === 'unique-local' || kind === 'loopback' || kind === 'unspecified',
    kind,
  };
}
