export type ValidationResult =
  | { ok: true; family: 'ipv4' | 'ipv6'; value: string }
  | { ok: false; error: string };

function isIPv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(s)) return false;
  if ((s.match(/::/g) ?? []).length > 1) return false;
  return s.includes(':');
}

export function validateCidr(input: string): ValidationResult {
  const s = input.trim();
  if (s === '') return { ok: false, error: 'Enter an address like 192.168.1.0/24' };

  const slash = s.lastIndexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const prefixStr = slash === -1 ? '' : s.slice(slash + 1);
  const prefix = prefixStr === '' ? NaN : Number(prefixStr);

  if (isIPv4(addr)) {
    if (slash !== -1 && (!Number.isInteger(prefix) || prefix < 0 || prefix > 32)) {
      return { ok: false, error: 'IPv4 prefix must be between 0 and 32' };
    }
    return { ok: true, family: 'ipv4', value: slash === -1 ? addr + '/32' : s };
  }

  if (isIPv6(addr)) {
    if (slash !== -1 && (!Number.isInteger(prefix) || prefix < 0 || prefix > 128)) {
      return { ok: false, error: 'IPv6 prefix must be between 0 and 128' };
    }
    return { ok: true, family: 'ipv6', value: slash === -1 ? addr + '/128' : s };
  }

  return { ok: false, error: 'Not a valid IPv4 or IPv6 address' };
}

export function formatNumber(n: number | bigint): string {
  if (typeof n === 'bigint') {
    if (n < 1000n) return n.toString();
    return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }
  if (n < 1000) return String(n);
  return Math.floor(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
