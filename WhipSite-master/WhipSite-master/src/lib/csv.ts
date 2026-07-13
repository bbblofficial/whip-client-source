// CSV export helper (browser download) used by list pages' bulk actions.
export function exportCsv<T>(rows: T[], name: string) {
  if (!rows.length) return;
  const recs = rows as Record<string, unknown>[];
  const keys = Object.keys(recs[0]).filter((k) => typeof recs[0][k] !== "object" || recs[0][k] === null);
  const csv = [keys.join(","), ...recs.map((r) => keys.map((k) => JSON.stringify(r[k] ?? "")).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = `whip-${name}.csv`;
  a.click();
}
