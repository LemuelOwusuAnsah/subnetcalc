import { analyze, split, type SubnetInfo } from '../lib/subnet';
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

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}

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

function ipv4ToBits(ip: string): string {
  return ip.split('.').map((p) => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 ? n.toString(2).padStart(8, '0') : '........';
  }).join('');
}

function renderBinaryIpv4(ip: string, cidr: number): void {
  const bits = ipv4ToBits(ip);
  const netBits = bits.slice(0, cidr);
  const hostBits = bits.slice(cidr);

  const dotted = (b: string) =>
    b.match(/.{1,8}/g)?.map((x) => x.padEnd(8, '.')).join('.') ?? '';

  binaryContent.innerHTML =
    '<span class="label">Address</span>' +
    '<div>' + dotted(bits) + '</div>' +
    '<span class="label" style="margin-top:0.75rem;">Network bits /' + cidr + '</span>' +
    '<div><span class="net">' + dotted(netBits) + '</span></div>' +
    '<span class="label" style="margin-top:0.5rem;">Host bits</span>' +
    '<div><span class="host">' + dotted(hostBits) + '</span></div>';
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
      const addressPart = v.value.slice(0, v.value.lastIndexOf('/'));
      renderBinaryIpv4(addressPart, info.cidr);
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
