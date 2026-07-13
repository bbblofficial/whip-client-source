"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · custom form controls: Popover, Dropdown, DatePicker, Combobox
//  Ported from the prototype (anchored portal popover, keyboard nav,
//  inner-scroll keeps the popover open).
// ════════════════════════════════════════════════════════════════════
import {
  useState,
  useRef,
  useEffect,
  useLayoutEffect,
  type ReactNode,
  type RefObject,
} from "react";
import { createPortal } from "react-dom";
import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Check,
  Calendar,
  X,
} from "lucide-react";
import { cn, fmtDate, NOW } from "@/lib/utils";

export interface Option {
  value: string;
  label: string;
  icon?: ReactNode;
  hint?: string;
}

function Popover({
  anchorRef,
  onClose,
  children,
  width,
  align = "left",
}: {
  anchorRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  children: ReactNode;
  width?: number;
  align?: "left" | "right";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; width: number } | null>(null);
  useLayoutEffect(() => {
    const a = anchorRef.current;
    if (!a) return;
    const r = a.getBoundingClientRect();
    const w = width || r.width;
    const estH = ref.current ? ref.current.offsetHeight : 280;
    const below = window.innerHeight - r.bottom;
    const openUp = below < estH + 12 && r.top > below;
    let left = align === "right" ? r.right - w : r.left;
    left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
    setPos({ left, top: openUp ? Math.max(8, r.top - estH - 6) : r.bottom + 6, width: w });
  }, [anchorRef, width, align]);
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (
        ref.current &&
        !ref.current.contains(e.target as Node) &&
        anchorRef.current &&
        !anchorRef.current.contains(e.target as Node)
      )
        onClose();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    const onResize = () => onClose();
    const onScroll = (e: Event) => {
      if (ref.current && ref.current.contains(e.target as Node)) return;
      onClose();
    };
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("keydown", onKey);
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [onClose, anchorRef]);
  return createPortal(
    <div
      ref={ref}
      className="whip-popover"
      style={pos ? { left: pos.left, top: pos.top, width: pos.width, visibility: "visible" } : { visibility: "hidden" }}
    >
      {children}
    </div>,
    document.body,
  );
}

export function Dropdown({
  value,
  onChange,
  options,
  placeholder = "Sélectionner…",
  size = "md",
  block = true,
  disabled,
  leftIcon,
  style,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Option[];
  placeholder?: string;
  size?: "md" | "sm";
  block?: boolean;
  disabled?: boolean;
  leftIcon?: ReactNode;
  style?: React.CSSProperties;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const btnRef = useRef<HTMLButtonElement>(null);
  const selected = options.find((o) => String(o.value) === String(value));
  useEffect(() => {
    if (open) {
      const i = options.findIndex((o) => String(o.value) === String(value));
      setActive(i < 0 ? 0 : i);
    }
  }, [open, options, value]);
  const choose = (o: Option) => {
    onChange(o.value);
    setOpen(false);
    btnRef.current?.focus();
  };
  return (
    <div className={cn("whip-dd", block && "whip-dd--block")} style={style}>
      <button
        ref={btnRef}
        type="button"
        disabled={disabled}
        className={cn(
          "whip-dd__btn",
          `whip-dd__btn--${size}`,
          open && "whip-dd__btn--open",
          !selected && "whip-dd__btn--placeholder",
        )}
        onClick={() => !disabled && setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (!open && (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {leftIcon && <span className="whip-dd__lefticon">{leftIcon}</span>}
        <span className="whip-dd__label">{selected ? selected.label : placeholder}</span>
        <ChevronDown size={16} className={cn("whip-dd__chev", open && "whip-dd__chev--open")} />
      </button>
      {open && (
        <Popover anchorRef={btnRef} onClose={() => setOpen(false)}>
          <div
            className="whip-dd__list"
            role="listbox"
            tabIndex={-1}
            ref={(el) => el?.focus()}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(options.length - 1, a + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(0, a - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                options[active] && choose(options[active]);
              }
            }}
          >
            {options.map((o, i) => (
              <button
                key={o.value}
                type="button"
                role="option"
                aria-selected={String(o.value) === String(value)}
                className={cn(
                  "whip-dd__opt",
                  String(o.value) === String(value) && "whip-dd__opt--selected",
                  i === active && "whip-dd__opt--active",
                )}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(o)}
              >
                {o.icon && <span className="whip-dd__opticon">{o.icon}</span>}
                <span className="whip-dd__optlabel">
                  {o.label}
                  {o.hint && <span className="whip-dd__opthint">{o.hint}</span>}
                </span>
                {String(o.value) === String(value) && <Check size={15} className="whip-dd__check" />}
              </button>
            ))}
          </div>
        </Popover>
      )}
    </div>
  );
}

const MONTHS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
const DOW = ["L", "M", "M", "J", "V", "S", "D"];
function sameDay(a: Date | null, b: Date | null) {
  return !!a && !!b && a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

export function DatePicker({
  value,
  onChange,
  size = "md",
  block = true,
  min,
  placeholder = "jj/mm/aaaa",
  quick = true,
}: {
  value: Date | string | null;
  onChange: (d: Date) => void;
  size?: "md" | "sm";
  block?: boolean;
  min?: Date | string;
  placeholder?: string;
  quick?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const val = value ? (value instanceof Date ? value : new Date(value)) : null;
  const [view, setView] = useState(() =>
    val ? new Date(val.getFullYear(), val.getMonth(), 1) : new Date(NOW.getFullYear(), NOW.getMonth(), 1),
  );
  const minD = min ? (min instanceof Date ? min : new Date(min)) : null;
  useEffect(() => {
    if (open && val) setView(new Date(val.getFullYear(), val.getMonth(), 1));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const first = new Date(view.getFullYear(), view.getMonth(), 1);
  const startDow = (first.getDay() + 6) % 7;
  const days = new Date(view.getFullYear(), view.getMonth() + 1, 0).getDate();
  const cells: (Date | null)[] = [];
  for (let i = 0; i < startDow; i++) cells.push(null);
  for (let d = 1; d <= days; d++) cells.push(new Date(view.getFullYear(), view.getMonth(), d));

  const pick = (d: Date) => {
    onChange(d);
    setOpen(false);
  };
  const addDays = (n: number) => {
    const d = new Date(NOW);
    d.setDate(d.getDate() + n);
    pick(d);
  };
  const disabled = (d: Date) => !!minD && d < new Date(minD.getFullYear(), minD.getMonth(), minD.getDate());

  return (
    <div className={cn("whip-dd", block && "whip-dd--block")}>
      <button
        ref={btnRef}
        type="button"
        className={cn("whip-dd__btn", `whip-dd__btn--${size}`, open && "whip-dd__btn--open", !val && "whip-dd__btn--placeholder")}
        onClick={() => setOpen((o) => !o)}
      >
        <Calendar size={15} className="whip-dd__lefticon" />
        <span className="whip-dd__label">{val ? fmtDate(val) : placeholder}</span>
        <ChevronDown size={16} className={cn("whip-dd__chev", open && "whip-dd__chev--open")} />
      </button>
      {open && (
        <Popover anchorRef={btnRef} onClose={() => setOpen(false)} width={282}>
          <div className="whip-cal">
            <div className="whip-cal__head">
              <button type="button" className="whip-cal__nav" onClick={() => setView(new Date(view.getFullYear(), view.getMonth() - 1, 1))}>
                <ChevronLeft size={16} />
              </button>
              <span className="whip-cal__title">
                {MONTHS[view.getMonth()]} {view.getFullYear()}
              </span>
              <button type="button" className="whip-cal__nav" onClick={() => setView(new Date(view.getFullYear(), view.getMonth() + 1, 1))}>
                <ChevronRight size={16} />
              </button>
            </div>
            <div className="whip-cal__dow">
              {DOW.map((d, i) => (
                <span key={i}>{d}</span>
              ))}
            </div>
            <div className="whip-cal__grid">
              {cells.map((d, i) =>
                d ? (
                  <button
                    key={i}
                    type="button"
                    disabled={disabled(d)}
                    className={cn("whip-cal__day", sameDay(d, val) && "whip-cal__day--sel", sameDay(d, NOW) && "whip-cal__day--today")}
                    onClick={() => pick(d)}
                  >
                    {d.getDate()}
                  </button>
                ) : (
                  <span key={i} />
                ),
              )}
            </div>
            {quick && (
              <div className="whip-cal__quick">
                {([["+7j", 7], ["+30j", 30], ["+90j", 90], ["+1 an", 365]] as [string, number][]).map(([l, n]) => (
                  <button key={l} type="button" className="whip-cal__quickbtn" onClick={() => addDays(n)}>
                    {l}
                  </button>
                ))}
              </div>
            )}
          </div>
        </Popover>
      )}
    </div>
  );
}

export function Combobox({
  value,
  onChange,
  options,
  placeholder = "Tapez ou sélectionnez…",
  size = "md",
  allowFree = true,
  leftIcon,
  clearable = true,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Option[];
  placeholder?: string;
  size?: "md" | "sm";
  allowFree?: boolean;
  leftIcon?: ReactNode;
  clearable?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const display = open ? query : value || "";
  const filtered = options.filter((o) => !query || o.label.toLowerCase().includes(query.toLowerCase()));
  useEffect(() => {
    if (open) setActive(0);
  }, [open, query]);
  const commit = (v: string) => {
    onChange(v);
    setOpen(false);
    setQuery("");
  };
  return (
    <div className="whip-dd whip-dd--block whip-combo" ref={wrapRef}>
      <div
        className={cn("whip-dd__btn", `whip-dd__btn--${size}`, open && "whip-dd__btn--open", !value && !open && "whip-dd__btn--placeholder")}
        onClick={() => {
          if (!open) {
            setQuery("");
            setOpen(true);
            inputRef.current?.focus();
          }
        }}
      >
        {leftIcon && <span className="whip-dd__lefticon">{leftIcon}</span>}
        <input
          ref={inputRef}
          className="whip-combo__input"
          value={display}
          placeholder={value || placeholder}
          onChange={(e) => {
            setQuery(e.target.value);
            if (!open) setOpen(true);
            if (allowFree) onChange(e.target.value);
          }}
          onFocus={() => {
            setQuery("");
            setOpen(true);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setOpen(true);
              setActive((a) => Math.min(filtered.length - 1, a + 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(0, a - 1));
            } else if (e.key === "Enter") {
              e.preventDefault();
              if (filtered[active]) commit(filtered[active].value);
              else if (allowFree) commit(query);
            } else if (e.key === "Escape") {
              setOpen(false);
            }
          }}
        />
        {clearable && value && (
          <button
            type="button"
            className="whip-combo__clear"
            onMouseDown={(e) => {
              e.preventDefault();
              commit("");
            }}
            title="Effacer"
          >
            <X size={14} />
          </button>
        )}
        <ChevronDown
          size={16}
          className={cn("whip-dd__chev", open && "whip-dd__chev--open")}
          onMouseDown={(e) => {
            e.preventDefault();
            setOpen((o) => !o);
            if (!open) inputRef.current?.focus();
          }}
        />
      </div>
      {open && (
        <Popover anchorRef={wrapRef} onClose={() => setOpen(false)}>
          <div className="whip-dd__list" role="listbox">
            {filtered.length === 0 ? (
              <div className="whip-combo__empty">
                {allowFree ? (
                  <>
                    Entrée pour utiliser « <strong>{query}</strong> »
                  </>
                ) : (
                  "Aucun résultat"
                )}
              </div>
            ) : (
              filtered.slice(0, 50).map((o, i) => (
                <button
                  key={o.value}
                  type="button"
                  role="option"
                  className={cn(
                    "whip-dd__opt",
                    String(o.value) === String(value) && "whip-dd__opt--selected",
                    i === active && "whip-dd__opt--active",
                  )}
                  onMouseEnter={() => setActive(i)}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    commit(o.value);
                  }}
                >
                  {o.icon && <span className="whip-dd__opticon">{o.icon}</span>}
                  <span className="whip-dd__optlabel">
                    {o.label}
                    {o.hint && <span className="whip-dd__opthint">{o.hint}</span>}
                  </span>
                  {String(o.value) === String(value) && <Check size={15} className="whip-dd__check" />}
                </button>
              ))
            )}
          </div>
        </Popover>
      )}
    </div>
  );
}

export { Popover };
