export type ExportFormat = 'txt' | 'csv';

export type ExportRow = {
  key: string;
  value: string;
};

export function toText(rows: ReadonlyArray<ExportRow>): string {
  const width = rows.reduce((w, r) => Math.max(w, r.key.length), 0);
  return rows.map((r) => r.key.padEnd(width) + '  ' + r.value).join('\n') + '\n';
}

export function toCsv(rows: ReadonlyArray<ExportRow>): string {
  const esc = (s: string) => '"' + s.replace(/"/g, '""') + '"';
  const lines = ['key,value', ...rows.map((r) => esc(r.key) + ',' + esc(r.value))];
  return lines.join('\n') + '\n';
}

export function download(filename: string, body: string, mime: string): void {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
