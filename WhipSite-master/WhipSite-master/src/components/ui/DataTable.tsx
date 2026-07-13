"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · DataTable — search, filters, sort, bulk-select, pagination
//  Ported from the prototype's <DataTable> (generic over row type).
// ════════════════════════════════════════════════════════════════════
import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Search,
  X,
  Filter,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { cn, fmtNum } from "@/lib/utils";
import { Checkbox, EmptyState } from "./primitives";
import { Dropdown } from "./inputs";

export interface Column<T> {
  key: string;
  label: string;
  width?: number | string;
  align?: "right" | "center";
  sortable?: boolean;
  sortValue?: (r: T) => string | number;
  render?: (r: T) => ReactNode;
}
export interface Filter<T> {
  key: string;
  label: string;
  options: { value: string; label: string }[];
  match?: (r: T, v: string) => boolean;
}
export interface BulkAction<T> {
  label: string;
  icon?: ReactNode;
  tone?: "danger";
  onClick: (rows: T[], clear: () => void) => void;
}

// Rows are opaque generics; read dynamic string keys through this helper.
function getField<T>(r: T, k: string): unknown {
  return (r as Record<string, unknown>)[k];
}

function SkeletonRows({ cols, rows = 8 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} className="whip-tr">
          {Array.from({ length: cols }).map((_, c) => (
            <td key={c} className="whip-td">
              <span className="whip-skel" style={{ width: `${40 + ((r + c) % 4) * 15}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function Pagination({
  page,
  pages,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
}) {
  if (total === 0) return null;
  const from = page * pageSize + 1;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <div className="whip-pagination">
      <span className="whip-pagination__info">
        {fmtNum(from)}–{fmtNum(to)} sur <strong>{fmtNum(total)}</strong>
      </span>
      <div className="whip-pagination__ctrl">
        <button className="whip-pagebtn" disabled={page === 0} onClick={() => onPage(page - 1)}>
          <ChevronLeft size={15} />
        </button>
        <span className="whip-pagination__page">
          {page + 1} / {pages}
        </span>
        <button className="whip-pagebtn" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>
          <ChevronRight size={15} />
        </button>
      </div>
    </div>
  );
}

export function DataTable<T>({
  columns,
  rows,
  rowKey = "id",
  searchKeys,
  searchPlaceholder = "Rechercher…",
  filters = [],
  rowActions,
  bulkActions,
  onRowClick,
  pageSize = 12,
  loading,
  error,
  onRetry,
  emptyState,
  defaultSort,
  dense,
  initialSearch,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey?: string;
  searchKeys?: string[];
  searchPlaceholder?: string;
  filters?: Filter<T>[];
  rowActions?: (r: T) => ReactNode;
  bulkActions?: BulkAction<T>[];
  onRowClick?: (r: T) => void;
  pageSize?: number;
  loading?: boolean;
  error?: boolean | string;
  onRetry?: () => void;
  emptyState?: { icon?: ReactNode; title: ReactNode; hint?: ReactNode; action?: ReactNode };
  defaultSort?: { key: string; dir: 1 | -1 };
  dense?: boolean;
  initialSearch?: string;
}) {
  const get = (r: T, k: string): unknown => getField(r, k);
  const [search, setSearch] = useState(initialSearch || "");
  const [filterVals, setFilterVals] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(defaultSort || null);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<unknown>>(() => new Set());

  useEffect(() => {
    setPage(0);
  }, [search, filterVals]);

  const filtered = useMemo(() => {
    let out = rows;
    const q = search.trim().toLowerCase();
    if (q && searchKeys) out = out.filter((r) => searchKeys.some((k) => String(get(r, k) ?? "").toLowerCase().includes(q)));
    for (const f of filters) {
      const v = filterVals[f.key];
      if (v && v !== "__all") out = out.filter((r) => (f.match ? f.match(r, v) : String(get(r, f.key)) === v));
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      const acc = col?.sortValue || ((r: T) => get(r, sort.key) as string | number);
      out = [...out].sort((a, b) => {
        let x = acc(a);
        let y = acc(b);
        if (x == null) x = "";
        if (y == null) y = "";
        if (typeof x === "string") return sort.dir * x.localeCompare(y as string);
        return sort.dir * ((x as number) - (y as number));
      });
    }
    return out;
  }, [rows, search, filterVals, sort, columns, filters, searchKeys]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageRows = filtered.slice(page * pageSize, (page + 1) * pageSize);
  const pageKeys = pageRows.map((r) => get(r, rowKey));
  const allSel = pageKeys.length > 0 && pageKeys.every((k) => selected.has(k));
  const someSel = pageKeys.some((k) => selected.has(k));

  const toggleSort = (k: string) =>
    setSort((s) => (s && s.key === k ? (s.dir === 1 ? { key: k, dir: -1 } : null) : { key: k, dir: 1 }));
  const toggleRow = (k: unknown) =>
    setSelected((s) => {
      const n = new Set(s);
      n.has(k) ? n.delete(k) : n.add(k);
      return n;
    });
  const toggleAll = () =>
    setSelected((s) => {
      const n = new Set(s);
      allSel ? pageKeys.forEach((k) => n.delete(k)) : pageKeys.forEach((k) => n.add(k));
      return n;
    });
  const clearSel = () => setSelected(new Set());
  const selRows = useMemo(() => rows.filter((r) => selected.has(get(r, rowKey))), [rows, selected, rowKey]);

  const colCount = columns.length + (bulkActions ? 1 : 0) + (rowActions ? 1 : 0);
  const hasToolbar = searchKeys || filters.length > 0;

  return (
    <div className="whip-table-wrap">
      {hasToolbar && (
        <div className="whip-toolbar">
          {searchKeys && (
            <div className="whip-search">
              <Search size={16} className="whip-search__ic" />
              <input
                className="whip-search__input"
                placeholder={searchPlaceholder}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              {search && (
                <button className="whip-search__clear" onClick={() => setSearch("")}>
                  <X size={14} />
                </button>
              )}
            </div>
          )}
          {filters.map((f) => (
            <div key={f.key} className="whip-filterdd">
              <Dropdown
                size="md"
                block={false}
                value={filterVals[f.key] || "__all"}
                onChange={(v) => setFilterVals((vals) => ({ ...vals, [f.key]: v }))}
                leftIcon={<Filter size={14} />}
                options={[{ value: "__all", label: f.label }, ...f.options]}
              />
            </div>
          ))}
        </div>
      )}

      {bulkActions && selected.size > 0 && (
        <div className="whip-bulkbar">
          <span className="whip-bulkbar__count">
            <strong>{selected.size}</strong> sélectionné{selected.size > 1 ? "s" : ""}
          </span>
          <div className="whip-bulkbar__actions">
            {bulkActions.map((a, i) => (
              <button
                key={i}
                className={cn("whip-bulkbtn", a.tone && `whip-bulkbtn--${a.tone}`)}
                onClick={() => a.onClick(selRows, clearSel)}
              >
                {a.icon}
                {a.label}
              </button>
            ))}
            <button className="whip-bulkbar__clear" onClick={clearSel}>
              <X size={14} />
              Annuler
            </button>
          </div>
        </div>
      )}

      <div className="whip-tablescroll">
        <table className={cn("whip-table", dense && "whip-table--dense")}>
          <thead>
            <tr>
              {bulkActions && (
                <th className="whip-th whip-th--check">
                  <Checkbox checked={allSel} indeterminate={someSel && !allSel} onChange={toggleAll} ariaLabel="Tout sélectionner" />
                </th>
              )}
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={cn("whip-th", c.align && `whip-th--${c.align}`, c.sortable && "whip-th--sortable")}
                  style={{ width: c.width }}
                  onClick={c.sortable ? () => toggleSort(c.key) : undefined}
                >
                  <span className="whip-th__inner">
                    {c.label}
                    {c.sortable &&
                      (sort && sort.key === c.key ? (
                        sort.dir === 1 ? (
                          <ChevronUp size={13} />
                        ) : (
                          <ChevronDown size={13} />
                        )
                      ) : (
                        <ChevronsUpDown size={13} className="whip-th__sorticon" />
                      ))}
                  </span>
                </th>
              ))}
              {rowActions && <th className="whip-th whip-th--right">actions</th>}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonRows cols={colCount} />
            ) : error ? (
              <tr>
                <td colSpan={colCount}>
                  <EmptyState
                    icon={<AlertTriangle size={26} />}
                    title="Erreur de chargement"
                    hint={typeof error === "string" ? error : "Impossible de joindre l'auth-server."}
                    action={
                      <button className="abs-btn abs-btn--secondary abs-btn--sm" onClick={onRetry}>
                        <RefreshCw size={14} />
                        Réessayer
                      </button>
                    }
                  />
                </td>
              </tr>
            ) : pageRows.length === 0 ? (
              <tr>
                <td colSpan={colCount}>
                  {emptyState ? (
                    <EmptyState {...emptyState} />
                  ) : (
                    <EmptyState icon={<Search size={24} />} title="Aucun résultat" hint="Ajuste ta recherche ou tes filtres." />
                  )}
                </td>
              </tr>
            ) : (
              pageRows.map((r) => (
                <tr
                  key={String(get(r, rowKey))}
                  className={cn(
                    "whip-tr",
                    onRowClick && "whip-tr--clickable",
                    selected.has(get(r, rowKey)) && "whip-tr--selected",
                  )}
                  onClick={onRowClick ? () => onRowClick(r) : undefined}
                >
                  {bulkActions && (
                    <td className="whip-td whip-td--check">
                      <Checkbox checked={selected.has(get(r, rowKey))} onChange={() => toggleRow(get(r, rowKey))} ariaLabel="Sélectionner la ligne" />
                    </td>
                  )}
                  {columns.map((c) => (
                    <td key={c.key} className={cn("whip-td", c.align && `whip-td--${c.align}`)} style={{ width: c.width }}>
                      {c.render ? c.render(r) : (get(r, c.key) as ReactNode)}
                    </td>
                  ))}
                  {rowActions && (
                    <td className="whip-td whip-td--right whip-td--actions">
                      <div className="whip-rowactions">{rowActions(r)}</div>
                    </td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {!loading && !error && <Pagination page={page} pages={pages} total={filtered.length} pageSize={pageSize} onPage={setPage} />}
    </div>
  );
}
