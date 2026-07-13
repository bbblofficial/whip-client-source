"use client";
// ════════════════════════════════════════════════════════════════════
//  WhipSite · SVG charts (ported from the prototype)
// ════════════════════════════════════════════════════════════════════
import { useEffect, useRef, useState, type ReactNode } from "react";
import { fmtNum } from "@/lib/utils";

function buildPath(data: number[], w: number, h: number, pad = 0) {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const step = (w - pad * 2) / (data.length - 1);
  return data
    .map((v, i) => {
      const x = pad + i * step;
      const y = h - pad - ((v - min) / range) * (h - pad * 2);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

export function Sparkline({
  data,
  w = 120,
  h = 36,
  color = "var(--whip-primary)",
  fill = true,
}: {
  data: number[];
  w?: number;
  h?: number;
  color?: string;
  fill?: boolean;
}) {
  const id = useRef("sp" + Math.random().toString(36).slice(2, 8)).current;
  const line = buildPath(data, w, h, 2);
  const area = `${line} L${w - 2},${h - 2} L2,${h - 2} Z`;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="whip-spark" preserveAspectRatio="none">
      {fill && (
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
      )}
      {fill && <path d={area} fill={`url(#${id})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function BarMini({
  data,
  w = 120,
  h = 36,
  color = "var(--whip-primary)",
}: {
  data: number[];
  w?: number;
  h?: number;
  color?: string;
}) {
  const max = Math.max(...data, 1);
  const bw = w / data.length;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="whip-spark">
      {data.map((v, i) => {
        const bh = (v / max) * (h - 2);
        return (
          <rect
            key={i}
            x={i * bw + bw * 0.18}
            y={h - bh}
            width={bw * 0.64}
            height={bh}
            rx="1"
            fill={color}
            opacity={0.45 + 0.55 * (v / max)}
          />
        );
      })}
    </svg>
  );
}

export function AreaChart({
  data,
  h = 220,
  color = "var(--whip-primary)",
  labels,
}: {
  data: number[];
  h?: number;
  color?: string;
  labels?: string[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  const id = useRef("ac" + Math.random().toString(36).slice(2, 8)).current;
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(() => ref.current && setW(ref.current.clientWidth));
    ro.observe(ref.current);
    setW(ref.current.clientWidth);
    return () => ro.disconnect();
  }, []);
  const padB = 26;
  const padT = 12;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const step = w / (data.length - 1 || 1);
  const pts = data.map((v, i) => [i * step, padT + (1 - (v - min) / range) * (h - padB - padT)]);
  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `${line} L${w},${h - padB} L0,${h - padB} Z`;
  return (
    <div
      ref={ref}
      className="whip-areachart"
      style={{ height: h }}
      onMouseLeave={() => setHover(null)}
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        const i = Math.round(((e.clientX - rect.left) / rect.width) * (data.length - 1));
        setHover(Math.max(0, Math.min(data.length - 1, i)));
      }}
    >
      <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.35" />
            <stop offset="100%" stopColor={color} stopOpacity="0.01" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((g) => (
          <line
            key={g}
            x1="0"
            x2={w}
            y1={padT + g * (h - padB - padT)}
            y2={padT + g * (h - padB - padT)}
            stroke="var(--whip-border)"
            strokeWidth="1"
            strokeDasharray="2 4"
          />
        ))}
        <path d={area} fill={`url(#${id})`} />
        <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
        {hover != null && (
          <>
            <line x1={pts[hover][0]} x2={pts[hover][0]} y1={padT} y2={h - padB} stroke={color} strokeWidth="1" strokeOpacity="0.4" />
            <circle cx={pts[hover][0]} cy={pts[hover][1]} r="4" fill={color} stroke="var(--whip-card)" strokeWidth="2" />
          </>
        )}
      </svg>
      {hover != null && (
        <div className="whip-areachart__tip" style={{ left: `${(pts[hover][0] / w) * 100}%` }}>
          <strong>{fmtNum(data[hover])}</strong>
          {labels && <span>{labels[hover]}</span>}
        </div>
      )}
    </div>
  );
}

export function Ring({
  value,
  total,
  size = 64,
  color = "var(--whip-primary)",
  track = "var(--whip-border-strong)",
  stroke = 7,
  children,
}: {
  value: number;
  total: number;
  size?: number;
  color?: string;
  track?: string;
  stroke?: number;
  children?: ReactNode;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const p = total ? value / total : 0;
  return (
    <div className="whip-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${c * p} ${c}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <div className="whip-ring__label">{children}</div>
    </div>
  );
}

export function Donut({
  segments,
  size = 150,
  centerLabel = "licences",
}: {
  segments: { value: number; color: string }[];
  size?: number;
  centerLabel?: string;
}) {
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  const r = size / 2 - 14;
  const c = 2 * Math.PI * r;
  const cx0 = size / 2;
  let off = 0;
  return (
    <div className="whip-donut" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={cx0} cy={cx0} r={r} fill="none" stroke="var(--whip-border)" strokeWidth="14" />
        {segments.map((s, i) => {
          const len = (s.value / total) * c;
          const el = (
            <circle
              key={i}
              cx={cx0}
              cy={cx0}
              r={r}
              fill="none"
              stroke={s.color}
              strokeWidth="14"
              strokeDasharray={`${len} ${c}`}
              strokeDashoffset={-off}
              transform={`rotate(-90 ${cx0} ${cx0})`}
              strokeLinecap="butt"
            />
          );
          off += len;
          return el;
        })}
      </svg>
      <div className="whip-donut__center">
        <div className="whip-donut__num">{fmtNum(total)}</div>
        <div className="whip-donut__lbl">{centerLabel}</div>
      </div>
    </div>
  );
}
