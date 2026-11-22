import { analyze, split, toBinaryWithSplit, type SubnetInfo } from '../lib/subnet';
import { analyzeIPv6, type IPv6Analysis } from '../lib/ipv6';
import { validateCidr, formatNumber } from '../lib/validate';
import { toText, toCsv, download, type ExportRow } from '../lib/export';

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error('missing #' + id);
  return el as T;
}

const cidrInput = $<HTMLInputElement>('cidrInput');
const analyzeBtn = $<HTMLButtonElement>('analyzeBtn');
const errorMsg = $<HTMLParagraphElement>('errorMsg');
const resultGrid = $<HTMLDivElement>('resultGrid');
const actions = $<HTMLDivElement>('actions');
const exportTxtBtn = $<HTMLButtonElement>('exportTxt');
const exportCsvBtn = $<HTMLButtonElement>('exportCsv');
const copyResultBtn = $<HTMLButtonElement>('copyResult');

const binaryCard = $<HTMLElement>('binaryCard');
const binaryContent = $<HTMLDivElement>('binaryContent');

const splitCard = $<HTMLElement>('splitCard');
const newPrefixEl = $<HTMLInputElement>('newPrefix');
const newPrefixVal = $<HTMLElement>('newPrefixVal');
const splitCount = $<HTMLParagraphElement>('splitCount');
const splitBtn = $<HTMLButtonElement>('splitBtn');
const splitError = $<HTMLParagraphElement>('splitError');
const splitResults = $<HTMLDivElement>('splitResults');

type LastAnalysis =
  | { family: 'ipv4'; value: string; info: SubnetInfo }
  | { family: 'ipv6'; value: string; info: IPv6Analysis }
  | null;

let last: LastAnalysis = null;

function rowsFromInfo(family: 'ipv4' | 'ipv6', info: SubnetInfo | IPv6Analysis): ExportRow[] {
  if (family === 'ipv4') {
    const i = info as SubnetInfo;
    return [
      { key: 'CIDR', value: '/' + i.cidr },
      { key: 'Network', value: i.networkAddress },
      { key: 'Broadcast', value: i.broadcastAddress },
      { key: 'First usable', value: i.firstUsable ?? '-' },
      { key: 'Last usable', value: i.lastUsable ?? '-' },
      { key: 'Total addresses', value: formatNumber(i.totalAddresses) },
      { key: 'Usable hosts', value: formatNumber(i.usableHosts) },
      { key: 'Subnet mask', value: i.subnetMask },
      { key: 'Wildcard mask', value: i.wildcardMask },
      { key: 'Class', value: i.ipClass },
      { key: 'Private', value: i.isPrivate ? 'yes' : 'no' },
    ];
  }
  const i = info as IPv6Analysis;
  return [
    { key: 'CIDR', value: '/' + i.prefix },
    { key: 'Compressed', value: i.compressed },
    { key: 'Expanded', value: i.expanded },
    { key: 'Network', value: i.networkAddress },
    { key: 'First address', value: i.firstAddress },
    { key: 'Last address', value: i.lastAddress },
    { key: 'Total addresses', value: formatNumber(i.totalAddresses) },
    { key: 'Kind', value: i.kind },
    { key: 'Private', value: i.isPrivate ? 'yes' : 'no' },
  ];
}

function renderGrid(rows: ExportRow[]): void {
  resultGrid.innerHTML = rows
    .map((r) => '<div class="row"><span class="key">' + escapeHtml(r.key) + '</span><span class="val">' + escapeHtml(r.value) + '</span></div>')
    .join('');
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}

function clearAll(): void {
  errorMsg.style.display = 'none';
  errorMsg.textContent = '';
  resultGrid.innerHTML = '';
  actions.style.display = 'none';
  binaryCard.style.display = 'none';
  splitCard.style.display = 'none';
  binaryContent.innerHTML = '';
  splitResults.innerHTML = '';
  splitError.style.display = 'none';
  last = null;
}

function showError(msg: string): void {
  clearAll();
  errorMsg.textContent = msg;
  errorMsg.style.display = '';
}

function renderBinaryIpv4(ip: string, cidr: number): void {
  const parts = toBinaryWithSplit(ip, cidr);
  const netBits = parts.network;
  const hostBits = parts.host;
  const netOctets: string[] = [];
  const hostOctets: string[] = [];
  for (let i = 0; i < 32; i += 8) {
    const nb = netBits.slice(Math.max(0, i), Math.min(i + 8, netBits.length));
    const hb = hostBits.slice(Math.max(0, i - netBits.length), Math.min(i + 8 - netBits.length, hostBits.length));
    if (nb.length + hb.length < 8 && i < netBits.length) {
      const tail = netBits.slice(i, i + 8);
      netOctets.push('<span class="net">' + (tail || '') + '</span>');
      hostOctets.push('');
    } else if (nb.length > 0 && hb.length === 0) {
      netOctets.push('<span class="net">' + nb.padEnd(8, '') + '</span>');
      hostOctets.push('');
    } else if (nb.length === 0 && hb.length > 0) {
      netOctets.push('');
      hostOctets.push('<span class="host">' + hb.padEnd(8, '') + '</span>');
    } else {
      netOctets.push(nb ? '<span class="net">' + nb + '</span>' : '');
      hostOctets.push(hb ? '<span class="host">' + hb + '</span>' : '');
    }
  }
  const netLine = netOctets.filter(Boolean).map((o) => o || '........').join('.');
  const hostLine = hostOctets.filter(Boolean).map((o) => o || '........').join('.');
  binaryContent.innerHTML =
    '<span class="label">Address</span>' +
    '<div>' + toBinaryDots(ip) + '</div>' +
    '<span class="label" style="margin-top:0.75rem;">Network / host split at /' + cidr + '</span>' +
    '<div>' + netLine + hostLine.replace(/<span class="host">/g, '<span class="host">') + '</div>';
}

function toBinaryDots(ip: string): string {
  const parts = ip.split('.');
  return parts.map((p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return '........';
    return n.toString(2).padStart(8, '0');
  }).join('.');
}

function renderBinaryIpv6(info: IPv6Analysis): void {
  const full = info.expanded.split(':').join('');
  const net = full.slice(0, info.prefix);
  const host = full.slice(info.prefix);
  binaryContent.innerHTML =
    '<span class="label">Expanded</span>' +
    '<div>' + info.expanded + '</div>' +
    '<span class="label" style="margin-top:0.75rem;">Binary (network / host)</span>' +
    '<div><span class="net">' + (net || '') + '</span><span class="host">' + (host || '') + '</span></div>';
}

function runAnalyze(): void {
  const input = cidrInput.value.trim();
  if (!input) {
    showError('Enter an address like 192.168.1.0/24');
    return;
  }
  const v = validateCidr(input);
  if (!v.ok) {
    showError(v.error);
    return;
  }

  try {
    if (v.family === 'ipv4') {
      const info = analyze(v.value);
      last = { family: 'ipv4', value: v.value, info };
      renderGrid(rowsFromInfo('ipv4', info));
      actions.style.display = '';
      binaryCard.style.display = '';
      splitCard.style.display = '';
      renderBinaryIpv4(info.networkAddress, info.cidr);
      setupSplit(info);
    } else {
      const info = analyzeIPv6(v.value);
      last = { family: 'ipv6', value: v.value, info };
      renderGrid(rowsFromInfo('ipv6', info));
      actions.style.display = '';
      binaryCard.style.display = '';
      splitCard.style.display = 'none';
      renderBinaryIpv6(info);
    }
    errorMsg.style.display = 'none';
  } catch (e) {
    showError(e instanceof Error ? e.message : 'invalid input');
  }
}

function setupSplit(info: SubnetInfo): void {
  newPrefixEl.min = String(info.cidr);
  newPrefixEl.max = '32';
  if (Number(newPrefixEl.value) < info.cidr) {
    newPrefixEl.value = String(info.cidr);
  }
  newPrefixVal.textContent = '/' + newPrefixEl.value;
  updateSplitCount(info);
  splitResults.innerHTML = '';
  splitError.style.display = 'none';
}

function updateSplitCount(info: SubnetInfo): void {
  const target = Number(newPrefixEl.value);
  if (target < info.cidr) {
    splitCount.textContent = 'Prefix must be /' + info.cidr + ' or larger.';
    return;
  }
  const count = Math.pow(2, target - info.cidr);
  splitCount.textContent = count + ' subnet' + (count === 1 ? '' : 's') + ' of /' + target;
}

function runSplit(): void {
  if (!last || last.family !== 'ipv4') return;
  splitError.style.display = 'none';
  try {
    const result = split(last.value, Number(newPrefixEl.value));
    const rows = result
      .map((s) => '<tr><td>' + s.index + '</td><td>' + s.networkAddress + '/' + s.cidr + '</td><td>' + s.broadcastAddress + '</td></tr>')
      .join('');
    splitResults.innerHTML =
      '<table><thead><tr><th>#</th><th>Network</th><th>Broadcast</th></tr></thead><tbody>' + rows + '</tbody></table>';
  } catch (e) {
    splitError.textContent = e instanceof Error ? e.message : 'split failed';
    splitError.style.display = '';
    splitResults.innerHTML = '';
  }
}

analyzeBtn.addEventListener('click', runAnalyze);
cidrInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runAnalyze();
});

newPrefixEl.addEventListener('input', () => {
  newPrefixVal.textContent = '/' + newPrefixEl.value;
  if (last && last.family === 'ipv4') updateSplitCount(last.info);
});

splitBtn.addEventListener('click', runSplit);

exportTxtBtn.addEventListener('click', () => {
  if (!last) return;
  const rows = rowsFromInfo(last.family, last.info);
  download('subnet.txt', toText(rows), 'text/plain');
});

exportCsvBtn.addEventListener('click', () => {
  if (!last) return;
  const rows = rowsFromInfo(last.family, last.info);
  download('subnet.csv', toCsv(rows), 'text/csv');
});

copyResultBtn.addEventListener('click', async () => {
  if (!last) return;
  const rows = rowsFromInfo(last.family, last.info);
  const text = toText(rows);
  try {
    await navigator.clipboard.writeText(text);
    const original = copyResultBtn.textContent;
    copyResultBtn.textContent = 'Copied';
    setTimeout(() => { copyResultBtn.textContent = original; }, 1200);
  } catch { return; }
});

cidrInput.value = '192.168.1.0/24';
runAnalyze();
